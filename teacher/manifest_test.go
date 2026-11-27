package teacher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleManifestFields() UpdateManifestFields {
	return UpdateManifestFields{
		Schema:     1,
		Platform:   "windows-x64",
		Sequence:   12,
		Version:    "0.2.0-alpha.1",
		MinUpdater: 1,
		IssuedAt:   1793610000,
		ExpiresAt:  1793613600,
		Size:       4096,
		SHA256:     strings.Repeat("a", 64),
	}
}

func TestSharedWindowsSignatureVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "update-manifest-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		PublicKey    string          `json:"public_key"`
		Manifest     json.RawMessage `json:"manifest"`
		SigningBytes string          `json:"signing_bytes"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	m, err := VerifyManifest(vector.Manifest, vector.PublicKey, 11, 1, 1793610000)
	if err != nil {
		t.Fatalf("verify shared vector failed: %v", err)
	}
	sb, err := SigningBytes(m.Fields())
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if string(sb) != vector.SigningBytes {
		t.Fatalf("signing bytes mismatch:\ngot:  %q\nwant: %q", string(sb), vector.SigningBytes)
	}
}

func TestManifestSignRoundtripAndRejections(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyHex(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fields := sampleManifestFields()
	signed, err := SignManifest(fields, key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyManifest(doc, pub, 11, 1, 1793610000)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	p, err := PackagePath(verified)
	if err != nil || p != "/api/device/update/package/"+strings.Repeat("a", 64) {
		t.Fatalf("unexpected package path: %q %v", p, err)
	}

	// Wrong keys / invalid points.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := PublicKeyHex(&otherKey.PublicKey)
	for _, badPub := range []string{otherPub, "04" + strings.Repeat("0", 128), strings.ToUpper(pub), "02" + strings.Repeat("a", 64), "", "04" + strings.Repeat("z", 128)} {
		if _, err := VerifyManifest(doc, badPub, 11, 1, 1793610000); err == nil {
			t.Fatalf("expected error for bad public key %q", badPub[:min(8, len(badPub))])
		}
	}

	// Tampering each authenticated field invalidates signature.
	var baseMap map[string]any
	_ = json.Unmarshal(doc, &baseMap)
	mutations := map[string]any{
		"sequence":    13,
		"version":     "0.2.0-alpha.2",
		"min_updater": 2,
		"issued_at":   fields.IssuedAt - 1,
		"expires_at":  fields.ExpiresAt + 1,
		"size":        4097,
		"sha256":      strings.Repeat("b", 64),
		"signature":   strings.Repeat("0", 128),
	}
	for k, v := range mutations {
		cp := make(map[string]any, len(baseMap))
		for bk, bv := range baseMap {
			cp[bk] = bv
		}
		cp[k] = v
		b, _ := json.Marshal(cp)
		if _, err := VerifyManifest(b, pub, 11, 1, 1793610000); err == nil {
			t.Fatalf("expected rejection when tampering field %s", k)
		}
	}

	// Unknown / missing fields.
	for _, extra := range []string{"url", "command", "public_key"} {
		cp := make(map[string]any, len(baseMap)+1)
		for bk, bv := range baseMap {
			cp[bk] = bv
		}
		cp[extra] = "bad"
		b, _ := json.Marshal(cp)
		if _, err := VerifyManifest(b, pub, 11, 1, 1793610000); err == nil {
			t.Fatalf("expected rejection for unknown field %s", extra)
		}
	}
	for k := range baseMap {
		cp := make(map[string]any, len(baseMap)-1)
		for bk, bv := range baseMap {
			if bk != k {
				cp[bk] = bv
			}
		}
		b, _ := json.Marshal(cp)
		if _, err := VerifyManifest(b, pub, 11, 1, 1793610000); err == nil {
			t.Fatalf("expected rejection for missing field %s", k)
		}
	}

	// Exact integer types and bounds.
	for _, field := range []string{"schema", "sequence", "min_updater", "issued_at", "expires_at", "size"} {
		for _, rawVal := range []string{"true", "false", `"1"`, "1.0", "-1", "0", "36893488147419103232", "null"} {
			cp := make(map[string]json.RawMessage, len(baseMap))
			for bk, bv := range baseMap {
				b, _ := json.Marshal(bv)
				cp[bk] = b
			}
			cp[field] = json.RawMessage(rawVal)
			b, _ := json.Marshal(cp)
			if _, err := VerifyManifest(b, pub, 11, 1, 1793610000); err == nil {
				t.Fatalf("expected rejection for %s=%s", field, rawVal)
			}
		}
	}

	// Replay & clock policy.
	for _, seq := range []int64{12, 13, MaxSequence} {
		if _, err := VerifyManifest(doc, pub, seq, 1, 1793610000); err == nil {
			t.Fatalf("expected replay rejection for installed=%d", seq)
		}
	}
	for _, now := range []int64{fields.IssuedAt - 301, fields.ExpiresAt, fields.ExpiresAt + 1} {
		if _, err := VerifyManifest(doc, pub, 11, 1, now); err == nil {
			t.Fatalf("expected time rejection for now=%d", now)
		}
	}
	if _, err := VerifyManifest(doc, pub, 11, 1, fields.IssuedAt-300); err != nil {
		t.Fatalf("clock skew -300 should be allowed: %v", err)
	}
	if _, err := VerifyManifest(doc, pub, 11, 1, fields.ExpiresAt-1); err != nil {
		t.Fatalf("expires_at-1 should be allowed: %v", err)
	}

	// Malformed, duplicate, deep, oversize, invalid UTF-8, surrogate JSON.
	docStr := string(doc)
	badDocs := [][]byte{
		[]byte("[]"),
		[]byte("null"),
		doc[:len(doc)-1],
		[]byte(docStr[:len(docStr)-1] + `,"sequence":12}`),
		[]byte(docStr[:len(docStr)-1] + `,"\u0073equence":12}`),
		[]byte(strings.Repeat("[", 2000) + "0" + strings.Repeat("]", 2000)),
		[]byte(docStr + strings.Repeat(" ", 4096)),
		{0xff, 0xfe},
		[]byte(`{"extra":"` + strings.Repeat("界", 1400) + `"}`),
		[]byte(`"\ud800"`),
	}
	for i, bad := range badDocs {
		if _, err := ParseManifest(bad); err == nil {
			t.Fatalf("expected ParseManifest error on badDoc[%d]", i)
		}
	}

	// Reject non-P256 key.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignManifest(fields, p384); err == nil {
		t.Fatal("expected error signing with P-384")
	}
	if _, err := PublicKeyHex(&p384.PublicKey); err == nil {
		t.Fatal("expected error encoding P-384 public key")
	}
}
