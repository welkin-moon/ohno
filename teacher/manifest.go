package teacher

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const (
	ManifestSchema  int64 = 1
	ManifestPlatform      = "windows-x64"
	MaxSequence     int64 = (1 << 53) - 1
	MaxPackageSize  int64 = 256 * 1024 * 1024
	MaxTimestamp    int64 = 253402300799 // Last second of year 9999.
	MaxValidity     int64 = 7 * 24 * 3600
	MaxDocumentSize       = 4096
	MaxClockSkew    int64 = 300
)

var (
	VersionRegexp = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})(?:-[a-z0-9](?:[a-z0-9.-]{0,31}))?$`)
	HexRegexp     = regexp.MustCompile(`^[0-9a-f]+$`)
)

// UpdateManifestFields represents the unsigned fields of an update offer.
type UpdateManifestFields struct {
	Schema     int64  `json:"schema"`
	Platform   string `json:"platform"`
	Sequence   int64  `json:"sequence"`
	Version    string `json:"version"`
	MinUpdater int64  `json:"min_updater"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}

// UpdateManifest represents a signed update offer.
type UpdateManifest struct {
	Schema     int64  `json:"schema"`
	Platform   string `json:"platform"`
	Sequence   int64  `json:"sequence"`
	Version    string `json:"version"`
	MinUpdater int64  `json:"min_updater"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Signature  string `json:"signature"`
}

func (m UpdateManifest) Fields() UpdateManifestFields {
	return UpdateManifestFields{
		Schema:     m.Schema,
		Platform:   m.Platform,
		Sequence:   m.Sequence,
		Version:    m.Version,
		MinUpdater: m.MinUpdater,
		IssuedAt:   m.IssuedAt,
		ExpiresAt:  m.ExpiresAt,
		Size:       m.Size,
		SHA256:     m.SHA256,
	}
}

func isLowerHex(s string, length int) bool {
	return len(s) == length && HexRegexp.MatchString(s)
}

// ValidateManifestFields enforces exact protocol bounds on unsigned manifest fields.
func ValidateManifestFields(f UpdateManifestFields) error {
	if f.Schema != ManifestSchema || f.Platform != ManifestPlatform {
		return errors.New("unsupported update format or platform")
	}
	if f.Sequence < 1 || f.Sequence > MaxSequence {
		return errors.New("invalid update sequence")
	}
	if !VersionRegexp.MatchString(f.Version) {
		return errors.New("invalid release version")
	}
	if f.MinUpdater < 1 || f.MinUpdater > 65535 {
		return errors.New("invalid minimum updater version")
	}
	if f.IssuedAt < 1 || f.IssuedAt > MaxTimestamp || f.ExpiresAt < 1 || f.ExpiresAt > MaxTimestamp {
		return errors.New("invalid update validity timestamps")
	}
	diff := f.ExpiresAt - f.IssuedAt
	if diff <= 0 || diff > MaxValidity {
		return errors.New("invalid update validity interval")
	}
	if f.Size < 1024 || f.Size > MaxPackageSize || !isLowerHex(f.SHA256, 64) {
		return errors.New("invalid update package identity")
	}
	return nil
}

// SigningBytes builds the canonical ASCII transcript shared with the native C++ client.
func SigningBytes(f UpdateManifestFields) ([]byte, error) {
	if err := ValidateManifestFields(f); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("ohno-update-p256-sha256-v1\n")
	b.WriteString(strconv.FormatInt(f.Schema, 10))
	b.WriteByte('\n')
	b.WriteString(f.Platform)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(f.Sequence, 10))
	b.WriteByte('\n')
	b.WriteString(f.Version)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(f.MinUpdater, 10))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(f.IssuedAt, 10))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(f.ExpiresAt, 10))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(f.Size, 10))
	b.WriteByte('\n')
	b.WriteString(f.SHA256)
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// PublicKeyHex returns the lowercase 130-char uncompressed SEC1 point (04 || X || Y) for a P-256 key.
func PublicKeyHex(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("release key must be P-256")
	}
	ecdhKey, err := pub.ECDH()
	if err != nil {
		return "", fmt.Errorf("release key must be valid P-256: %w", err)
	}
	return hex.EncodeToString(ecdhKey.Bytes()), nil
}

// ParsePinnedPublicKey parses a lowercase 130-char uncompressed SEC1 P-256 public key.
func ParsePinnedPublicKey(pinned string) (*ecdsa.PublicKey, error) {
	if !isLowerHex(pinned, 130) || !strings.HasPrefix(pinned, "04") {
		return nil, errors.New("invalid pinned release key")
	}
	raw, err := hex.DecodeString(pinned)
	if err != nil || len(raw) != 65 {
		return nil, errors.New("invalid pinned release key")
	}
	// Validate the point lies on P-256 via crypto/ecdh.
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, errors.New("invalid pinned release key point")
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// SignManifest signs fields with a P-256 ECDSA key, encoding signature as 64-byte big-endian r || s hex.
func SignManifest(f UpdateManifestFields, key *ecdsa.PrivateKey) (UpdateManifest, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return UpdateManifest{}, errors.New("release key must be P-256")
	}
	transcript, err := SigningBytes(f)
	if err != nil {
		return UpdateManifest{}, err
	}
	digest := sha256.Sum256(transcript)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return UpdateManifest{}, err
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return UpdateManifest{
		Schema:     f.Schema,
		Platform:   f.Platform,
		Sequence:   f.Sequence,
		Version:    f.Version,
		MinUpdater: f.MinUpdater,
		IssuedAt:   f.IssuedAt,
		ExpiresAt:  f.ExpiresAt,
		Size:       f.Size,
		SHA256:     f.SHA256,
		Signature:  hex.EncodeToString(sig[:]),
	}, nil
}

// ParseManifest strictly parses a signed update manifest JSON document without verifying its signature.
func ParseManifest(document []byte) (UpdateManifest, error) {
	if len(document) > MaxDocumentSize {
		return UpdateManifest{}, errors.New("invalid update document size")
	}
	obj, err := ParseStrictJSONObject(document)
	if err != nil {
		return UpdateManifest{}, fmt.Errorf("invalid update JSON: %w", err)
	}
	if len(obj) != 10 {
		return UpdateManifest{}, errors.New("unknown or missing signed update field")
	}
	getStr := func(name string) (string, bool) {
		v, ok := obj[name]
		if !ok {
			return "", false
		}
		s, ok := v.(string)
		return s, ok
	}
	schema, ok := StrictInt64(obj["schema"], 1, 1)
	if !ok {
		return UpdateManifest{}, errors.New("unsupported update format or platform")
	}
	platform, ok := getStr("platform")
	if !ok || platform != ManifestPlatform {
		return UpdateManifest{}, errors.New("unsupported update format or platform")
	}
	sequence, ok := StrictInt64(obj["sequence"], 1, MaxSequence)
	if !ok {
		return UpdateManifest{}, errors.New("invalid update sequence")
	}
	version, ok := getStr("version")
	if !ok {
		return UpdateManifest{}, errors.New("invalid release version")
	}
	minUpdater, ok := StrictInt64(obj["min_updater"], 1, 65535)
	if !ok {
		return UpdateManifest{}, errors.New("invalid minimum updater version")
	}
	issuedAt, ok := StrictInt64(obj["issued_at"], 1, MaxTimestamp)
	if !ok {
		return UpdateManifest{}, errors.New("invalid update validity timestamps")
	}
	expiresAt, ok := StrictInt64(obj["expires_at"], 1, MaxTimestamp)
	if !ok {
		return UpdateManifest{}, errors.New("invalid update validity timestamps")
	}
	size, ok := StrictInt64(obj["size"], 1024, MaxPackageSize)
	if !ok {
		return UpdateManifest{}, errors.New("invalid update package identity")
	}
	sum, ok := getStr("sha256")
	if !ok {
		return UpdateManifest{}, errors.New("invalid update package identity")
	}
	sig, ok := getStr("signature")
	if !ok || !isLowerHex(sig, 128) {
		return UpdateManifest{}, errors.New("invalid update signature format")
	}
	m := UpdateManifest{
		Schema:     schema,
		Platform:   platform,
		Sequence:   sequence,
		Version:    version,
		MinUpdater: minUpdater,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
		Size:       size,
		SHA256:     sum,
		Signature:  sig,
	}
	if err := ValidateManifestFields(m.Fields()); err != nil {
		return UpdateManifest{}, err
	}
	return m, nil
}

// VerifyManifest authenticates an update offer against a pinned P-256 public key
// and enforces replay floor, updater compatibility, and validity timestamps.
func VerifyManifest(document []byte, pinnedPublicKey string, installedSequence, updaterVersion, now int64) (UpdateManifest, error) {
	if installedSequence < 0 || installedSequence > MaxSequence ||
		updaterVersion < 1 || updaterVersion > 65535 ||
		now < 1 || now > MaxTimestamp {
		return UpdateManifest{}, errors.New("invalid trusted update context")
	}
	m, err := ParseManifest(document)
	if err != nil {
		return UpdateManifest{}, err
	}
	pub, err := ParsePinnedPublicKey(pinnedPublicKey)
	if err != nil {
		return UpdateManifest{}, err
	}
	sigBytes, err := hex.DecodeString(m.Signature)
	if err != nil || len(sigBytes) != 64 {
		return UpdateManifest{}, errors.New("update signature not trusted")
	}
	transcript, err := SigningBytes(m.Fields())
	if err != nil {
		return UpdateManifest{}, err
	}
	digest := sha256.Sum256(transcript)
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || !ecdsa.Verify(pub, digest[:], r, s) {
		return UpdateManifest{}, errors.New("update signature not trusted")
	}
	if m.Sequence <= installedSequence {
		return UpdateManifest{}, errors.New("update sequence already applied or replayed")
	}
	if m.MinUpdater > updaterVersion {
		return UpdateManifest{}, errors.New("updater is too old")
	}
	if m.IssuedAt > now+MaxClockSkew || m.ExpiresAt <= now {
		return UpdateManifest{}, errors.New("update expired or not yet valid")
	}
	return m, nil
}

// PackagePath returns the fixed same-origin package download path for a manifest.
func PackagePath(m UpdateManifest) (string, error) {
	if err := ValidateManifestFields(m.Fields()); err != nil {
		return "", err
	}
	return "/api/device/update/package/" + m.SHA256, nil
}
