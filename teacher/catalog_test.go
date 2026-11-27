package teacher

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogLifecycleAndFaults(t *testing.T) {
	root := filepath.Join(t.TempDir(), "releases")
	cat, err := InitializeReleaseCatalog(root)
	if err != nil {
		t.Fatalf("initialize catalog: %v", err)
	}
	defer func() {
		if cat != nil {
			cat.Close()
		}
	}()

	verifyPrivateDirectoryACL(t, root)

	// Re-initializing must fail without touching existing key.
	origKey, err := os.ReadFile(filepath.Join(root, "release-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeReleaseCatalog(root); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected ErrExist on re-init, got %v", err)
	}
	afterKey, _ := os.ReadFile(filepath.Join(root, "release-key.pem"))
	if !bytes.Equal(origKey, afterKey) {
		t.Fatal("re-init modified release key")
	}

	// Explicit approval, pause, and higher sequence.
	if offer, err := cat.Offer(1000); err != nil || offer != nil {
		t.Fatalf("expected nil initial offer, got %+v %v", offer, err)
	}
	payload := FixturePackage("0.2.0")
	offer, err := cat.Approve(payload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	offerJSON, _ := json.Marshal(offer)
	verified, err := VerifyManifest(offerJSON, cat.PublicKey, 0, 1, 1000)
	if err != nil || verified != offer {
		t.Fatalf("verify offer failed: %v", err)
	}
	gotPkg, err := cat.Package(offer.SHA256, 1000)
	if err != nil || !bytes.Equal(gotPkg, payload) {
		t.Fatalf("package read failed: %v", err)
	}
	if p, err := cat.Package("../release-key.pem", 1000); err != nil || p != nil {
		t.Fatalf("traversal package should return nil, got %d %v", len(p), err)
	}
	if expired, err := cat.Offer(offer.ExpiresAt); err != nil || expired != nil {
		t.Fatalf("expired offer should be nil, got %+v %v", expired, err)
	}
	if err := cat.Pause(); err != nil {
		t.Fatal(err)
	}
	if paused, err := cat.Offer(1000); err != nil || paused != nil || cat.HighWater() != 1 {
		t.Fatalf("pause mismatch: offer=%+v hw=%d err=%v", paused, cat.HighWater(), err)
	}
	second, err := cat.Approve(payload, &ApproveOptions{Now: 1001, Lifetime: 86400, MinUpdater: 1})
	if err != nil || second.Sequence != 2 {
		t.Fatalf("second approve mismatch: %+v %v", second, err)
	}
	pubKey := cat.PublicKey
	cat.Close()
	cat, err = OpenReleaseCatalog(root)
	if err != nil {
		t.Fatalf("reopen catalog: %v", err)
	}
	if cat.PublicKey != pubKey {
		t.Fatal("public key changed after reopen")
	}
	reopenedOffer, err := cat.Offer(1001)
	if err != nil || reopenedOffer == nil || *reopenedOffer != second {
		t.Fatalf("reopened offer mismatch: %+v %v", reopenedOffer, err)
	}

	// Exclusive lock prevents concurrent open.
	if _, err := OpenReleaseCatalog(root); err == nil {
		t.Fatal("expected lock conflict on second open")
	}
}

func TestCatalogPersistFaultsAndIntegrity(t *testing.T) {
	// Persist failure poisons instance without advancing disk state.
	root1 := filepath.Join(t.TempDir(), "r1")
	cat, err := InitializeReleaseCatalog(root1)
	if err != nil {
		t.Fatal(err)
	}
	payload := FixturePackage("0.2.0")
	first, err := cat.Approve(payload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1})
	if err != nil {
		t.Fatal(err)
	}
	origReplace := catalogReplace
	catalogReplace = func(src, dst string) error { return errors.New("fixture disk failure") }
	_, approveErr := cat.Approve(payload, &ApproveOptions{Now: 1001, Lifetime: 86400, MinUpdater: 1})
	catalogReplace = origReplace
	if approveErr == nil {
		t.Fatal("expected error on replace failure")
	}
	if _, err := cat.Offer(1001); err == nil {
		t.Fatal("poisoned catalog must refuse offer")
	}
	cat.Close()
	cat, err = OpenReleaseCatalog(root1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cat.Offer(1001); err != nil || got == nil || *got != first {
		t.Fatalf("expected original offer after failed replace, got %+v %v", got, err)
	}
	if next, err := cat.Approve(payload, &ApproveOptions{Now: 1002, Lifetime: 86400, MinUpdater: 1}); err != nil || next.Sequence != 2 {
		t.Fatalf("expected seq 2 after recovery, got %+v %v", next, err)
	}
	cat.Close()

	// Ambiguous landed write preserves higher sequence on reopen.
	root2 := filepath.Join(t.TempDir(), "r2")
	cat2, err := InitializeReleaseCatalog(root2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cat2.Approve(payload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1}); err != nil {
		t.Fatal(err)
	}
	catalogReplace = func(src, dst string) error {
		if err := origReplace(src, dst); err != nil {
			return err
		}
		return errors.New("fixture failure after rename")
	}
	_, ambigErr := cat2.Approve(payload, &ApproveOptions{Now: 1001, Lifetime: 86400, MinUpdater: 1})
	catalogReplace = origReplace
	if ambigErr == nil {
		t.Fatal("expected error on ambiguous write")
	}
	if _, err := cat2.Offer(1001); err == nil {
		t.Fatal("poisoned catalog must refuse offer")
	}
	cat2.Close()
	cat2, err = OpenReleaseCatalog(root2)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cat2.Offer(1001); err != nil || got == nil || got.Sequence != 2 {
		t.Fatalf("expected landed seq 2, got %+v %v", got, err)
	}
	if next, err := cat2.Approve(payload, &ApproveOptions{Now: 1002, Lifetime: 86400, MinUpdater: 1}); err != nil || next.Sequence != 3 {
		t.Fatalf("expected seq 3, got %+v %v", next, err)
	}
	cat2.Close()

	// Tampered package, corrupt catalog, missing key never regenerate.
	root3 := filepath.Join(t.TempDir(), "r3")
	cat3, err := InitializeReleaseCatalog(root3)
	if err != nil {
		t.Fatal(err)
	}
	for _, badPayload := range [][]byte{{}, append([]byte("MZ"), bytes.Repeat([]byte("x"), 1024)...)} {
		if _, err := cat3.Approve(badPayload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1}); err == nil {
			t.Fatal("expected invalid payload rejection")
		}
	}
	for _, badOpts := range []*ApproveOptions{
		{Now: 1000, Lifetime: 0, MinUpdater: 1},
		{Now: 1000, Lifetime: 604801, MinUpdater: 1},
		{Now: 1000, Lifetime: 86400, MinUpdater: 0},
	} {
		if _, err := cat3.Approve(payload, badOpts); err == nil {
			t.Fatal("expected invalid approval options rejection")
		}
	}
	if cat3.HighWater() != 0 {
		t.Fatalf("high water advanced on invalid approvals: %d", cat3.HighWater())
	}
	offer3, err := cat3.Approve(payload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root3, offer3.SHA256+".ohno"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cat3.Package(offer3.SHA256, 1000); err == nil {
		t.Fatal("expected tamper error reading package")
	}
	if _, err := cat3.Approve(payload, &ApproveOptions{Now: 1000, Lifetime: 86400, MinUpdater: 1}); err == nil {
		t.Fatal("expected tamper error re-approving package")
	}
	cat3.Close()
	if err := os.WriteFile(filepath.Join(root3, "catalog.json"), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReleaseCatalog(root3); err == nil {
		t.Fatal("expected error opening corrupt catalog")
	}
	keyPath := filepath.Join(root3, "release-key.pem")
	_ = os.Remove(keyPath)
	if _, err := OpenReleaseCatalog(root3); err == nil {
		t.Fatal("expected error with missing key")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("missing key must never be regenerated")
	}
}
