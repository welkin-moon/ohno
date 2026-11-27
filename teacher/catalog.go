package teacher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CatalogError indicates a trust, integrity, or durability error in the release catalog.
type CatalogError struct {
	Msg string
	Err error
}

func (e *CatalogError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *CatalogError) Unwrap() error { return e.Err }

// Test hooks for fault injection in unit tests.
var (
	catalogReplace = durableReplaceImpl
	catalogSync    = syncFile
)

type catalogState struct {
	Schema    int64           `json:"schema"`
	HighWater int64           `json:"high_water"`
	Current   *UpdateManifest `json:"current"`
}

// ReleaseCatalog manages explicit teacher-approved immutable releases and P-256 signing identity.
type ReleaseCatalog struct {
	root      string
	statePath string
	keyPath   string
	lockFile  *os.File
	key       *ecdsa.PrivateKey
	PublicKey string
	mu        sync.Mutex
	poisoned  bool
	data      catalogState
}

func atomicWriteFile(path string, data []byte, replaceFn func(string, string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ohno-release-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := catalogSync(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFn(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// InitializeReleaseCatalog creates a brand-new private release directory and P-256 signing key.
// Fails if the directory already exists; never replaces a lost or corrupted key.
func InitializeReleaseCatalog(directory string) (*ReleaseCatalog, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := CreatePrivateDirectory(root); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	kf, err := os.OpenFile(filepath.Join(root, "release-key.pem"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := kf.Write(pemBytes); err != nil {
		kf.Close()
		return nil, err
	}
	if err := catalogSync(kf); err != nil {
		kf.Close()
		return nil, err
	}
	if err := kf.Close(); err != nil {
		return nil, err
	}
	initial := []byte(`{"schema":1,"high_water":0,"current":null}`)
	if err := atomicWriteFile(filepath.Join(root, "catalog.json"), initial, catalogReplace); err != nil {
		return nil, err
	}
	return OpenReleaseCatalog(root)
}

// OpenReleaseCatalog opens and exclusively locks an existing release catalog directory.
func OpenReleaseCatalog(directory string) (*ReleaseCatalog, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, &CatalogError{Msg: "missing trusted release directory"}
	}
	c := &ReleaseCatalog{
		root:      root,
		statePath: filepath.Join(root, "catalog.json"),
		keyPath:   filepath.Join(root, "release-key.pem"),
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	lf, err := openExclusiveLock(filepath.Join(root, "catalog.lock"))
	if err != nil {
		return nil, err
	}
	c.lockFile = lf
	if err := checkRegularPrivateFile(c.keyPath); err != nil {
		return nil, err
	}
	if err := checkRegularPrivateFile(c.statePath); err != nil {
		return nil, err
	}
	kInfo, err := os.Stat(c.keyPath)
	if err != nil {
		return nil, err
	}
	sInfo, err := os.Stat(c.statePath)
	if err != nil {
		return nil, err
	}
	if kInfo.Size() > 4096 || sInfo.Size() > 8192 {
		return nil, &CatalogError{Msg: "release trust file too large"}
	}
	rawKey, err := os.ReadFile(c.keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, &CatalogError{Msg: "invalid release private key PEM"}
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ecKey, err2 := x509.ParseECPrivateKey(block.Bytes); err2 == nil {
			parsedKey = ecKey
		} else {
			return nil, &CatalogError{Msg: "invalid release private key", Err: err}
		}
	}
	ecKey, isEC := parsedKey.(*ecdsa.PrivateKey)
	if !isEC || ecKey.Curve != elliptic.P256() {
		return nil, &CatalogError{Msg: "release key must be P-256"}
	}
	pubHex, err := PublicKeyHex(&ecKey.PublicKey)
	if err != nil {
		return nil, &CatalogError{Msg: "invalid release public key", Err: err}
	}
	c.key = ecKey
	c.PublicKey = pubHex

	rawState, err := os.ReadFile(c.statePath)
	if err != nil {
		return nil, err
	}
	state, err := c.parseState(rawState)
	if err != nil {
		return nil, err
	}
	c.data = state
	ok = true
	return c, nil
}

// Close releases the exclusive catalog file lock.
func (c *ReleaseCatalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lockFile != nil {
		_ = c.lockFile.Close()
		c.lockFile = nil
	}
}

// HighWater returns the current durable sequence high-water mark.
func (c *ReleaseCatalog) HighWater() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.HighWater
}

func (c *ReleaseCatalog) parseState(document []byte) (catalogState, error) {
	if len(document) > 8192 {
		return catalogState{}, &CatalogError{Msg: "catalog too large"}
	}
	obj, err := ParseStrictJSONObject(document)
	if err != nil {
		return catalogState{}, &CatalogError{Msg: "invalid catalog", Err: err}
	}
	if len(obj) != 3 {
		return catalogState{}, &CatalogError{Msg: "invalid catalog fields"}
	}
	schema, ok1 := StrictInt64(obj["schema"], 1, 1)
	hw, ok2 := StrictInt64(obj["high_water"], 0, MaxSequence)
	rawCurrent, hasCurrent := obj["current"]
	if !ok1 || !ok2 || !hasCurrent {
		return catalogState{}, &CatalogError{Msg: "invalid catalog fields"}
	}
	state := catalogState{Schema: schema, HighWater: hw}
	if rawCurrent != nil {
		curBytes, err := json.Marshal(rawCurrent)
		if err != nil {
			return catalogState{}, &CatalogError{Msg: "invalid catalog current offer", Err: err}
		}
		parsed, err := ParseManifest(curBytes)
		if err != nil {
			return catalogState{}, &CatalogError{Msg: "catalog signature not trusted", Err: err}
		}
		verified, err := VerifyManifest(curBytes, c.PublicKey, 0, 65535, parsed.IssuedAt)
		if err != nil {
			return catalogState{}, &CatalogError{Msg: "catalog signature not trusted", Err: err}
		}
		if verified.Sequence != hw {
			return catalogState{}, &CatalogError{Msg: "catalog replay floor mismatch"}
		}
		state.Current = &verified
	}
	return state, nil
}

func (c *ReleaseCatalog) readyLocked() error {
	if c.poisoned || c.lockFile == nil {
		return &CatalogError{Msg: "catalog unavailable; reopen and verify storage"}
	}
	return nil
}

func (c *ReleaseCatalog) saveLocked(next catalogState) error {
	if err := c.readyLocked(); err != nil {
		return err
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return &CatalogError{Msg: "failed to encode catalog", Err: err}
	}
	if _, err := c.parseState(encoded); err != nil {
		return err
	}
	if err := atomicWriteFile(c.statePath, encoded, catalogReplace); err != nil {
		// Rename/fsync failures can be ambiguous. Poison this instance so memory
		// cannot expose an uncommitted decision or reset a sequence.
		c.poisoned = true
		return &CatalogError{Msg: "catalog write failed; restart and inspect", Err: err}
	}
	c.data = next
	return nil
}

// ApproveOption customizes release approval timestamps and compatibility bounds.
type ApproveOptions struct {
	Now        int64
	Lifetime   int64
	MinUpdater int64
}

// Approve validates, durably persists, signs, and publishes a fixed-layout update package.
func (c *ReleaseCatalog) Approve(pkg []byte, opts *ApproveOptions) (UpdateManifest, error) {
	parsed, err := ParsePackage(pkg)
	if err != nil {
		return UpdateManifest{}, err
	}
	now := time.Now().Unix()
	var lifetime int64 = 86400
	var minUpdater int64 = 1
	if opts != nil {
		if opts.Now != 0 {
			now = opts.Now
		}
		lifetime = opts.Lifetime
		minUpdater = opts.MinUpdater
	}
	if lifetime <= 0 || lifetime > MaxValidity || minUpdater < 1 || minUpdater > 65535 || now < 1 || now > MaxTimestamp {
		return UpdateManifest{}, errors.New("invalid approval parameters")
	}
	sum := sha256.Sum256(pkg)
	digest := hex.EncodeToString(sum[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.readyLocked(); err != nil {
		return UpdateManifest{}, err
	}
	seq := c.data.HighWater + 1
	fields := UpdateManifestFields{
		Schema:     1,
		Platform:   ManifestPlatform,
		Sequence:   seq,
		Version:    parsed.Version,
		MinUpdater: minUpdater,
		IssuedAt:   now,
		ExpiresAt:  now + lifetime,
		Size:       int64(len(pkg)),
		SHA256:     digest,
	}
	manifest, err := SignManifest(fields, c.key)
	if err != nil {
		return UpdateManifest{}, err
	}
	pkgPath := filepath.Join(c.root, digest+".ohno")
	if _, statErr := os.Lstat(pkgPath); statErr == nil {
		if err := checkRegularPrivateFile(pkgPath); err != nil {
			return UpdateManifest{}, err
		}
		existing, err := os.ReadFile(pkgPath)
		if err != nil {
			return UpdateManifest{}, &CatalogError{Msg: "immutable package read failed", Err: err}
		}
		existingSum := sha256.Sum256(existing)
		if len(existing) != len(pkg) || hex.EncodeToString(existingSum[:]) != digest {
			return UpdateManifest{}, &CatalogError{Msg: "immutable package was changed"}
		}
	} else if os.IsNotExist(statErr) {
		if err := atomicWriteFile(pkgPath, pkg, catalogReplace); err != nil {
			return UpdateManifest{}, &CatalogError{Msg: "package persistence failed", Err: err}
		}
	} else {
		return UpdateManifest{}, &CatalogError{Msg: "package inspection failed", Err: statErr}
	}
	// Package is durable BEFORE the signed approval becomes visible.
	next := catalogState{Schema: 1, HighWater: seq, Current: &manifest}
	if err := c.saveLocked(next); err != nil {
		return UpdateManifest{}, err
	}
	return manifest, nil
}

// Pause immediately stops offering or authorizing updates without lowering the high-water mark.
func (c *ReleaseCatalog) Pause() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.readyLocked(); err != nil {
		return err
	}
	return c.saveLocked(catalogState{Schema: 1, HighWater: c.data.HighWater, Current: nil})
}

// Offer returns the currently approved valid manifest, or nil if paused or expired.
func (c *ReleaseCatalog) Offer(now int64) (*UpdateManifest, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.readyLocked(); err != nil {
		return nil, err
	}
	if c.data.Current == nil {
		return nil, nil
	}
	raw, err := json.Marshal(c.data.Current)
	if err != nil {
		return nil, nil
	}
	verified, err := VerifyManifest(raw, c.PublicKey, 0, 65535, now)
	if err != nil {
		return nil, nil
	}
	return &verified, nil
}

// Package returns the raw bytes of the currently approved package matching digest.
func (c *ReleaseCatalog) Package(digest string, now int64) ([]byte, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.readyLocked(); err != nil {
		return nil, err
	}
	if c.data.Current == nil {
		return nil, nil
	}
	raw, err := json.Marshal(c.data.Current)
	if err != nil {
		return nil, nil
	}
	current, err := VerifyManifest(raw, c.PublicKey, 0, 65535, now)
	if err != nil || digest != current.SHA256 {
		return nil, nil
	}
	pkgPath := filepath.Join(c.root, current.SHA256+".ohno")
	if err := checkRegularPrivateFile(pkgPath); err != nil {
		return nil, err
	}
	fi, err := os.Stat(pkgPath)
	if err != nil {
		return nil, &CatalogError{Msg: "approved package unavailable", Err: err}
	}
	if fi.Size() != current.Size {
		return nil, &CatalogError{Msg: "approved package size changed"}
	}
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, &CatalogError{Msg: "approved package read failed", Err: err}
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) > MaxPackageSize || hex.EncodeToString(sum[:]) != current.SHA256 {
		return nil, &CatalogError{Msg: "approved package integrity changed"}
	}
	return data, nil
}
