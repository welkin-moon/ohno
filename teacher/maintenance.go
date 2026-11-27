package teacher

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	MaintenanceIterations  = 600_000
	MaintenanceWindow      = 300.0
	MaintenancePerSource   = 8
	MaintenanceGlobalLimit = 32
)

var (
	SaltRegexp = regexp.MustCompile(`^[0-9a-f]{32}$`)
	HashRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)
	IDRegexp   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// MaintenanceCredential stores the server-side salted PBKDF2-HMAC-SHA256 verifier.
type MaintenanceCredential struct {
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Digest     string `json:"digest"`
}

// MaintenanceAuthRequest is the parsed request to /api/maintenance/authorize.
type MaintenanceAuthRequest struct {
	Action              string
	Nonce               string
	MaintenancePassword string
	HasDevice           bool
	DeviceID            string
	DeviceKey           string
}

// ParseAuthorizationRequest strictly validates a /api/maintenance/authorize JSON body.
func ParseAuthorizationRequest(raw []byte) (MaintenanceAuthRequest, error) {
	if len(raw) > 2048 {
		return MaintenanceAuthRequest{}, errors.New("maintenance request too large")
	}
	obj, err := ParseStrictJSONObject(raw)
	if err != nil {
		return MaintenanceAuthRequest{}, errors.New("invalid maintenance JSON")
	}
	action, ok1 := obj["action"].(string)
	nonce, ok2 := obj["nonce"].(string)
	password, ok3 := obj["maintenance_password"].(string)
	if !ok1 || !ok2 || !ok3 || (action != "install" && action != "uninstall") || !HashRegexp.MatchString(nonce) {
		return MaintenanceAuthRequest{}, errors.New("invalid maintenance request")
	}
	req := MaintenanceAuthRequest{
		Action:              action,
		Nonce:               nonce,
		MaintenancePassword: password,
	}
	if len(obj) == 3 {
		return req, nil
	}
	if len(obj) == 5 && action == "uninstall" {
		devID, okID := obj["device_id"].(string)
		devKey, okKey := obj["device_key"].(string)
		if !okID || !okKey || !IDRegexp.MatchString(devID) || !IDRegexp.MatchString(devKey) {
			return MaintenanceAuthRequest{}, errors.New("invalid maintenance device identity")
		}
		req.HasDevice = true
		req.DeviceID = devID
		req.DeviceKey = devKey
		return req, nil
	}
	return MaintenanceAuthRequest{}, errors.New("invalid maintenance request")
}

// PasswordBytes validates a 12–128 rune printable UTF-8 maintenance passphrase (<= 512 bytes).
func PasswordBytes(password string) ([]byte, error) {
	if !utf8.ValidString(password) {
		return nil, errors.New("invalid maintenance password encoding")
	}
	runes := 0
	for _, r := range password {
		if r < 32 || r == 127 {
			return nil, errors.New("maintenance password must be 12-128 printable characters")
		}
		runes++
	}
	if runes < 12 || runes > 128 {
		return nil, errors.New("maintenance password must be 12-128 printable characters")
	}
	if len(password) > 512 {
		return nil, errors.New("maintenance password is too long")
	}
	return []byte(password), nil
}

func pbkdf2SHA256(password, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), salt, iterations, 32)
}

// CreateCredential generates a salted PBKDF2-HMAC-SHA256 verifier.
func CreateCredential(password string) (*MaintenanceCredential, error) {
	encoded, err := PasswordBytes(password)
	if err != nil {
		return nil, err
	}
	var saltBytes [16]byte
	if _, err := rand.Read(saltBytes[:]); err != nil {
		return nil, err
	}
	digest, err := pbkdf2SHA256(encoded, saltBytes[:], MaintenanceIterations)
	if err != nil {
		return nil, err
	}
	return &MaintenanceCredential{
		Algorithm:  "pbkdf2-sha256",
		Iterations: MaintenanceIterations,
		Salt:       hex.EncodeToString(saltBytes[:]),
		Digest:     hex.EncodeToString(digest),
	}, nil
}

// ValidCredential verifies that a stored credential record has exact expected parameters.
func ValidCredential(c *MaintenanceCredential) bool {
	return c != nil &&
		c.Algorithm == "pbkdf2-sha256" &&
		c.Iterations == MaintenanceIterations &&
		SaltRegexp.MatchString(c.Salt) &&
		HashRegexp.MatchString(c.Digest)
}

type maintenanceAttempt struct {
	when   float64
	source string
}

// MaintenanceGuard bounds CPU, retained sources, and aggregate verification attempts.
type MaintenanceGuard struct {
	clock   func() float64
	derive  func(password, salt []byte, iterations int) ([]byte, error)
	mu      sync.Mutex
	attempts []maintenanceAttempt
	workers chan struct{}
}

// NewMaintenanceGuard creates a MaintenanceGuard with standard monotonic clock and PBKDF2.
func NewMaintenanceGuard() *MaintenanceGuard {
	start := time.Now()
	return &MaintenanceGuard{
		clock:  func() float64 { return time.Since(start).Seconds() },
		derive: pbkdf2SHA256,
		workers: make(chan struct{}, 2),
	}
}

// Verify checks password against credential under per-source, global, and concurrency limits.
func (g *MaintenanceGuard) Verify(password string, credential *MaintenanceCredential, source string) bool {
	encoded, err := PasswordBytes(password)
	if err != nil {
		return false
	}
	if !ValidCredential(credential) || len(source) > 128 {
		return false
	}
	salt, err := hex.DecodeString(credential.Salt)
	if err != nil {
		return false
	}
	g.mu.Lock()
	now := g.clock()
	cut := 0
	for cut < len(g.attempts) && now-g.attempts[cut].when >= MaintenanceWindow {
		cut++
	}
	if cut > 0 {
		g.attempts = append(g.attempts[:0], g.attempts[cut:]...)
	}
	perSource := 0
	for _, a := range g.attempts {
		if a.source == source {
			perSource++
		}
	}
	if len(g.attempts) >= MaintenanceGlobalLimit || perSource >= MaintenancePerSource {
		g.mu.Unlock()
		return false
	}
	select {
	case g.workers <- struct{}{}:
	default:
		g.mu.Unlock()
		return false
	}
	g.attempts = append(g.attempts, maintenanceAttempt{when: now, source: source})
	g.mu.Unlock()

	defer func() { <-g.workers }()
	actual, err := g.derive(encoded, salt, MaintenanceIterations)
	if err != nil {
		return false
	}
	actualHex := hex.EncodeToString(actual)
	return subtle.ConstantTimeCompare([]byte(actualHex), []byte(credential.Digest)) == 1
}

// AttemptCount returns the current number of retained attempts (for testing).
func (g *MaintenanceGuard) AttemptCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.attempts)
}
