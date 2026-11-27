package integration

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/welkin-moon/ohno/teacher"
)

// TestUpdatePackageParity verifies Go and native C++ OHNOPK01 parsers agree on
// deterministic and pseudo-random mutations. Set OHNO_UPDATE_PACKAGE_TEST to the
// compiled C++ update-package-test binary path.
func TestUpdatePackageParity(t *testing.T) {
	client := os.Getenv("OHNO_UPDATE_PACKAGE_TEST")
	if client == "" {
		t.Skip("set OHNO_UPDATE_PACKAGE_TEST to run native/Go package parser parity test")
	}
	absClient, err := filepath.Abs(client)
	if err != nil {
		t.Fatal(err)
	}
	original := fixturePackage(t, "0.2.0", nil)
	rng := rand.New(rand.NewSource(891))

	cases := [][]byte{
		original,
		original[:len(original)-1],
		append(append([]byte{}, original...), []byte("extra")...),
	}
	positions := make([]int, 0, 80)
	for i := 0; i < 65; i++ {
		positions = append(positions, i)
	}
	for _, off := range []int{0, 1, 0x3c, 0x3d, 0x3e, 0x3f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x94, 0x98, 0x99} {
		positions = append(positions, 65+off)
	}
	for _, pos := range positions {
		for _, b := range []byte{0, 1, 255} {
			cp := append([]byte{}, original...)
			cp[pos] = b
			cases = append(cases, cp)
		}
	}
	for i := 0; i < 100; i++ {
		cp := append([]byte{}, original...)
		cp[rng.Intn(len(cp))] = byte(rng.Intn(256))
		cases = append(cases, cp)
	}

	tmpPath := filepath.Join(t.TempDir(), "package.ohno")
	for idx, data := range cases {
		_, goErr := teacher.ParsePackage(data)
		expectedOK := goErr == nil
		if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(absClient, tmpPath)
		err := cmd.Run()
		nativeOK := err == nil
		if nativeOK != expectedOK {
			t.Fatalf("parser disagreement on mutation %d: goOK=%v nativeOK=%v", idx, expectedOK, nativeOK)
		}
	}
	t.Logf("%d Go/native package parser cases agree", len(cases))
}
