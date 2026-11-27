package teacher

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	MaxRequests   = 10000
	PINIterations = 160000
)

var (
	MACRegexp         = regexp.MustCompile(`^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	ProgramNameRegexp = regexp.MustCompile(`^[a-z0-9_. +-]{1,128}\.exe$`)
	PINRegexp         = regexp.MustCompile(`^[0-9]{4,8}$`)

	DefaultWebDomains = []string{"classic.minecraft.net", "eaglercraft.com"}
	DefaultGameNames  = []string{
		"plantsvszombies.exe", "plantsvszombiesoriginal.exe", "slaythespire.exe",
		"gta3.exe", "gta-vc.exe", "gta_sa.exe", "gtaiv.exe",
		"minecraftlauncher.exe", "minecraft.windows.exe",
	}
	DefaultProgramFeatures = []string{
		"orig:plantsvszombies.exe",
		"orig:minecraftlauncher.exe",
		"orig:steam.exe",
		"orig:wegame.exe",
		"product:minecraft",
		"product:plants vs. zombies",
		"product:steam",
		"product:wegame",
		"company:valve",
		"company:epic games",
		"company:riot games",
		"company:mihoyo",
		"company:rockstar",
		"company:popcap",
		"title:minecraft",
		"title:植物大战僵尸",
		"path:steamapps",
	}
	DefaultAllowProgramNames = []string{
		"msedge.exe", "chrome.exe", "firefox.exe",
		"winword.exe", "excel.exe", "powerpnt.exe",
		"wps.exe", "et.exe", "wpp.exe",
		"code.exe", "devcpp.exe", "notepad++.exe", "python.exe",
	}
	DefaultAllowProgramFeatures = []string{
		"signer:microsoft corporation",
		"company:kingsoft",
	}
)

// StateSaveError indicates that persisting state.json failed and in-memory state was rolled back.
type StateSaveError struct {
	Err error
}

func (e *StateSaveError) Error() string {
	if e.Err != nil {
		return "cannot save teacher state: " + e.Err.Error()
	}
	return "cannot save teacher state"
}

func (e *StateSaveError) Unwrap() error { return e.Err }

// Test hooks for state persistence fault injection.
var (
	storeCreateTemp = os.CreateTemp
	storeSync       = syncFile
	storeReplace    = os.Rename
)

// DeviceRecord represents a registered student machine in state.json.
type DeviceRecord struct {
	Name       string   `json:"name"`
	KeyHash    string   `json:"key_hash"`
	Approved   bool     `json:"approved"`
	BoundMAC   string   `json:"bound_mac"`
	MACs       []string `json:"macs"`
	PrimaryMAC string   `json:"primary_mac"`
	LastIP     string   `json:"last_ip"`
	LastSeen   int64    `json:"last_seen"`
	TUN        *bool    `json:"tun"`
	WFP        *bool    `json:"wfp"`
}

// RequestRecord represents an approval request or temporary grant.
type RequestRecord struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"`
	Object   string `json:"object"`
	Label    string `json:"label"`
	State    string `json:"state"`
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires,omitempty"`
}

// MaintenanceEvent records a persisted maintenance authorization decision (no secrets).
type MaintenanceEvent struct {
	Action       string `json:"action"`
	Nonce        string `json:"nonce"`
	DeviceID     string `json:"device_id"`
	AuthorizedAt int64  `json:"authorized_at"`
	ExpiresAt    int64  `json:"expires_at"`
}

// StateData is the on-disk schema for state.json (version 1).
type StateData struct {
	Version               int                      `json:"version"`
	UnlockPINSalt         *string                  `json:"unlock_pin_salt"`
	UnlockPINHash         *string                  `json:"unlock_pin_hash"`
	PolicyRevision        int                      `json:"policy_revision"`
	WebMode               string                   `json:"web_mode"`
	WebDomains            []string                 `json:"web_domains"`
	AllowWebDomains       []string                 `json:"allow_web_domains"`
	ProgramMode           string                   `json:"program_mode"`
	ProgramHashes         []string                 `json:"program_hashes"`
	ProgramNames          []string                 `json:"program_names"`
	ProgramFeatures       []string                 `json:"program_features"`
	AllowProgramHashes    []string                 `json:"allow_program_hashes"`
	AllowProgramNames     []string                 `json:"allow_program_names"`
	AllowProgramFeatures  []string                 `json:"allow_program_features"`
	BlockLocalFiles       bool                     `json:"block_local_files"`
	Devices               map[string]*DeviceRecord `json:"devices"`
	Requests              []*RequestRecord         `json:"requests"`
	MaintenanceCredential *MaintenanceCredential   `json:"maintenance_credential,omitempty"`
	MaintenanceEvents     []MaintenanceEvent       `json:"maintenance_events,omitempty"`
}

// ValidPolicyMode reports whether mode is "blacklist" or "whitelist".
func ValidPolicyMode(mode string) bool {
	return mode == "blacklist" || mode == "whitelist"
}

// ValidFeatureRule matches src/feature_match.hpp valid_feature_rule exactly.
func ValidFeatureRule(rule string) bool {
	if len(rule) == 0 || len(rule) > 160 || !utf8.ValidString(rule) {
		return false
	}
	for i := 0; i < len(rule); i++ {
		if rule[i] < 32 || rule[i] == 127 {
			return false
		}
	}
	body := rule
	if colon := strings.IndexByte(rule, ':'); colon >= 0 {
		prefix := rule[:colon]
		switch prefix {
		case "any", "orig", "product", "company", "desc", "signer", "title", "path":
			body = rule[colon+1:]
		default:
			return false
		}
	}
	for i := 0; i < len(body); i++ {
		if body[i] > 32 {
			return true
		}
	}
	return false
}

// ValidText verifies printable UTF-8 text within [min, limit] runes.
func ValidText(value string, limit int, allowEmpty bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	runes := 0
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
		runes++
	}
	minLen := 1
	if allowEmpty {
		minLen = 0
	}
	return runes >= minLen && runes <= limit
}

// ValidMAC checks canonical lowercase nonzero unicast MAC format.
func ValidMAC(value string) bool {
	if !MACRegexp.MatchString(value) || value == "00:00:00:00:00:00" {
		return false
	}
	firstByte, err := strconv.ParseUint(value[:2], 16, 8)
	return err == nil && (firstByte&1) == 0
}

// MACBound returns true when dev has a bound MAC present in its current MAC inventory.
func MACBound(dev *DeviceRecord) bool {
	if dev == nil || dev.BoundMAC == "" {
		return false
	}
	for _, m := range dev.MACs {
		if m == dev.BoundMAC {
			return true
		}
	}
	return false
}

func pinHash(pin, saltHex string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", err
	}
	out, err := pbkdf2SHA256([]byte(pin), salt, PINIterations)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(out), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func tokenURLSafe(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func normalizeStateData(d *StateData) {
	if !ValidPolicyMode(d.WebMode) {
		d.WebMode = "blacklist"
	}
	if !ValidPolicyMode(d.ProgramMode) {
		d.ProgramMode = "blacklist"
	}
	if d.WebDomains == nil {
		d.WebDomains = []string{}
	}
	if d.AllowWebDomains == nil {
		d.AllowWebDomains = []string{}
	}
	if d.ProgramHashes == nil {
		d.ProgramHashes = []string{}
	}
	if d.ProgramNames == nil {
		d.ProgramNames = []string{}
	}
	if d.ProgramFeatures == nil {
		d.ProgramFeatures = []string{}
	}
	if d.AllowProgramHashes == nil {
		d.AllowProgramHashes = []string{}
	}
	if d.AllowProgramNames == nil {
		d.AllowProgramNames = []string{}
	}
	if d.AllowProgramFeatures == nil {
		d.AllowProgramFeatures = []string{}
	}
	if d.Devices == nil {
		d.Devices = map[string]*DeviceRecord{}
	}
	for _, dev := range d.Devices {
		if dev.MACs == nil {
			dev.MACs = []string{}
		}
	}
	if d.Requests == nil {
		d.Requests = []*RequestRecord{}
	}
}

func releaseDirForState(statePath string) string {
	base := filepath.Base(statePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		stem = base
	}
	return filepath.Join(filepath.Dir(statePath), stem+".releases")
}

// Store owns the persisted teacher state, maintenance verifier, PIN throttling, and release catalog.
type Store struct {
	Path                 string
	ReleaseDirectory     string
	mu                   sync.Mutex
	committed            []byte
	Data                 StateData
	attempts             map[string][]time.Time
	MaintenanceGuard     *MaintenanceGuard
	ReleaseCatalog       *ReleaseCatalog
	ReleaseError         bool
	ReleaseDownloadSlots chan struct{}
	// Optional hook for testing concurrent device revocation during package read.
	packageReader func(digest string) ([]byte, error)
}

// InitializeStore creates a new state.json (failing if it already exists) and opens it.
func InitializeStore(path string) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, os.ErrExist
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	initial := StateData{
		Version:              1,
		UnlockPINSalt:        nil,
		UnlockPINHash:        nil,
		PolicyRevision:       0,
		WebMode:              "blacklist",
		WebDomains:           append([]string{}, DefaultWebDomains...),
		AllowWebDomains:      []string{},
		ProgramMode:          "blacklist",
		ProgramHashes:        []string{},
		ProgramNames:         append([]string{}, DefaultGameNames...),
		ProgramFeatures:      append([]string{}, DefaultProgramFeatures...),
		AllowProgramHashes:   []string{},
		AllowProgramNames:    append([]string{}, DefaultAllowProgramNames...),
		AllowProgramFeatures: append([]string{}, DefaultAllowProgramFeatures...),
		BlockLocalFiles:      false,
		Devices:              map[string]*DeviceRecord{},
		Requests:             []*RequestRecord{},
	}
	raw, err := json.Marshal(initial)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return OpenStore(path)
}

// OpenStore loads an existing state.json, runs legacy migrations, and opens any existing release catalog.
func OpenStore(path string) (*Store, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rawMap map[string]any
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return nil, err
	}
	var data StateData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	if data.Version != 1 {
		return nil, errors.New("unsupported state version")
	}
	normalizeStateData(&data)

	s := &Store{
		Path:                 path,
		ReleaseDirectory:     releaseDirForState(path),
		committed:            raw,
		Data:                 data,
		attempts:             map[string][]time.Time{},
		MaintenanceGuard:     NewMaintenanceGuard(),
		ReleaseDownloadSlots: make(chan struct{}, 2),
	}
	if _, statErr := os.Stat(s.ReleaseDirectory); statErr == nil {
		cat, err := OpenReleaseCatalog(s.ReleaseDirectory)
		if err != nil {
			// Never replace lost/corrupt school signing identity automatically.
			s.ReleaseError = true
		} else {
			s.ReleaseCatalog = cat
		}
	}

	// Legacy migrations: drop alpha.3 salt/password_hash and compact duplicate pending rows.
	migrated := false
	if _, ok := rawMap["salt"]; ok {
		migrated = true
	}
	if _, ok := rawMap["password_hash"]; ok {
		migrated = true
	}
	if _, ok := rawMap["unlock_pin_salt"]; !ok {
		migrated = true
	}
	if _, ok := rawMap["unlock_pin_hash"]; !ok {
		migrated = true
	}
	type reqKey struct{ dev, kind, obj string }
	seen := map[reqKey]struct{}{}
	keptRev := make([]*RequestRecord, 0, len(s.Data.Requests))
	for i := len(s.Data.Requests) - 1; i >= 0; i-- {
		item := s.Data.Requests[i]
		k := reqKey{item.DeviceID, item.Kind, item.Object}
		if item.State == "pending" {
			if _, exists := seen[k]; exists {
				migrated = true
				continue
			}
			seen[k] = struct{}{}
		}
		keptRev = append(keptRev, item)
	}
	compacted := make([]*RequestRecord, len(keptRev))
	for i := range keptRev {
		compacted[len(keptRev)-1-i] = keptRev[i]
	}
	s.Data.Requests = compacted
	if migrated {
		if err := s.Save(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close releases any open release catalog file lock.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ReleaseCatalog != nil {
		s.ReleaseCatalog.Close()
		s.ReleaseCatalog = nil
	}
}

func (s *Store) saveLocked() error {
	normalizeStateData(&s.Data)
	encoded, err := json.Marshal(s.Data)
	if err != nil {
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	f, err := storeCreateTemp(filepath.Dir(s.Path), ".ohno-*")
	if err != nil {
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(encoded); err != nil {
		f.Close()
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	if err := storeSync(f); err != nil {
		f.Close()
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	if err := f.Close(); err != nil {
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	if err := storeReplace(tmp, s.Path); err != nil {
		s.rollbackLocked()
		return &StateSaveError{Err: err}
	}
	cleanup = false
	s.committed = encoded
	return nil
}

func (s *Store) rollbackLocked() {
	var restored StateData
	if err := json.Unmarshal(s.committed, &restored); err == nil {
		normalizeStateData(&restored)
		s.Data = restored
	}
}

// Save atomically persists state.json and rolls back in-memory state on any error.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// InitializeReleases explicitly initializes the school P-256 release signing identity.
func (s *Store) InitializeReleases() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ReleaseCatalog != nil {
		return &CatalogError{Msg: "release trust already exists; restore rather than regenerate"}
	}
	if _, err := os.Stat(s.ReleaseDirectory); err == nil {
		return &CatalogError{Msg: "release trust already exists; restore rather than regenerate"}
	}
	cat, err := InitializeReleaseCatalog(s.ReleaseDirectory)
	if err != nil {
		return err
	}
	s.ReleaseCatalog = cat
	s.ReleaseError = false
	return nil
}

// SetUnlockPIN configures or disables the optional 4-8 digit classroom unlock PIN.
func (s *Store) SetUnlockPIN(pin *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pin == nil {
		s.Data.UnlockPINSalt = nil
		s.Data.UnlockPINHash = nil
	} else {
		if !PINRegexp.MatchString(*pin) {
			return errors.New("unlock PIN must be 4-8 digits")
		}
		var saltBytes [16]byte
		if _, err := rand.Read(saltBytes[:]); err != nil {
			return err
		}
		salt := hex.EncodeToString(saltBytes[:])
		digest, err := pinHash(*pin, salt)
		if err != nil {
			return err
		}
		s.Data.UnlockPINSalt = &salt
		s.Data.UnlockPINHash = &digest
	}
	clear(s.attempts)
	return s.saveLocked()
}

// VerifyUnlockPIN checks the classroom PIN under per-device failure rate limits.
func (s *Store) VerifyUnlockPIN(pin, address string) bool {
	if !PINRegexp.MatchString(pin) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Data.UnlockPINSalt == nil || s.Data.UnlockPINHash == nil || *s.Data.UnlockPINSalt == "" || *s.Data.UnlockPINHash == "" {
		return false
	}
	now := time.Now()
	prev := s.attempts[address]
	active := prev[:0]
	for _, t := range prev {
		if now.Sub(t) < 300*time.Second {
			active = append(active, t)
		}
	}
	if len(active) >= 8 {
		s.attempts[address] = active
		return false
	}
	actual, err := pinHash(pin, *s.Data.UnlockPINSalt)
	if err != nil || subtle.ConstantTimeCompare([]byte(actual), []byte(*s.Data.UnlockPINHash)) != 1 {
		s.attempts[address] = append(active, now)
		return false
	}
	delete(s.attempts, address)
	return true
}

// SetMaintenancePassword sets or disables the teacher maintenance password.
// PBKDF2 hashing runs outside the store lock.
func (s *Store) SetMaintenancePassword(password *string) error {
	var cred *MaintenanceCredential
	if password != nil {
		var err error
		cred, err = CreateCredential(*password)
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Data.MaintenanceCredential = cred
	return s.saveLocked()
}

func sameCredential(a, b *MaintenanceCredential) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (s *Store) deviceLocked(devID, key string, requireApproved bool) *DeviceRecord {
	dev, ok := s.Data.Devices[devID]
	if !ok || dev == nil {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(dev.KeyHash), []byte(sha256Hex(key))) != 1 {
		return nil
	}
	if requireApproved && (!dev.Approved || !MACBound(dev)) {
		return nil
	}
	return dev
}

// AuthorizeMaintenance verifies maintenance credentials outside the policy lock and persists an audit record.
func (s *Store) AuthorizeMaintenance(password, source, action, nonce, devID, key string) (*MaintenanceEvent, error) {
	if (action != "install" && action != "uninstall") || !HashRegexp.MatchString(nonce) {
		return nil, nil
	}
	s.mu.Lock()
	var credCopy *MaintenanceCredential
	if s.Data.MaintenanceCredential != nil {
		c := *s.Data.MaintenanceCredential
		credCopy = &c
	}
	if action == "uninstall" && s.deviceLocked(devID, key, false) == nil {
		s.mu.Unlock()
		return nil, nil
	}
	s.mu.Unlock()

	if !s.MaintenanceGuard.Verify(password, credCopy, source) {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Rotation/disable during a slow hash must invalidate that result.
	if !sameCredential(s.Data.MaintenanceCredential, credCopy) {
		return nil, nil
	}
	if action == "uninstall" && s.deviceLocked(devID, key, false) == nil {
		return nil, nil
	}
	now := time.Now().Unix()
	ev := MaintenanceEvent{
		Action:       action,
		Nonce:        nonce,
		DeviceID:     "",
		AuthorizedAt: now,
		ExpiresAt:    now + 120,
	}
	if action == "uninstall" {
		ev.DeviceID = devID
	}
	events := append(s.Data.MaintenanceEvents, ev)
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	s.Data.MaintenanceEvents = events
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return &ev, nil
}

func (s *Store) addRequestLocked(devID, kind, obj, label string, approved bool) (*RequestRecord, error) {
	now := time.Now().Unix()
	for _, item := range s.Data.Requests {
		if item.DeviceID == devID && item.Kind == kind && item.Object == obj &&
			(item.State == "pending" || (item.State == "approved" && item.Expires > now)) {
			if approved {
				item.State = "approved"
				item.Expires = now + 3600
				if err := s.saveLocked(); err != nil {
					return nil, err
				}
			}
			cp := *item
			return &cp, nil
		}
	}
	if len(s.Data.Requests) >= MaxRequests {
		finished := -1
		for i, item := range s.Data.Requests {
			if item.State != "pending" && (item.State != "approved" || item.Expires <= now) {
				finished = i
				break
			}
		}
		if finished < 0 {
			return nil, nil
		}
		s.Data.Requests = append(s.Data.Requests[:finished], s.Data.Requests[finished+1:]...)
	}
	state := "pending"
	var expires int64
	if approved {
		state = "approved"
		expires = now + 3600
	}
	item := &RequestRecord{
		ID:       tokenURLSafe(18),
		DeviceID: devID,
		Kind:     kind,
		Object:   obj,
		Label:    label,
		State:    state,
		Created:  now,
		Expires:  expires,
	}
	s.Data.Requests = append(s.Data.Requests, item)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	cp := *item
	return &cp, nil
}
