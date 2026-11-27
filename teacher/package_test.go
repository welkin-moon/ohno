package teacher

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// FixtureExe builds a minimal 1024-byte valid Windows x64 PE32+ header fixture.
func FixtureExe() []byte {
	data := make([]byte, 1024)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:0x84], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(data[0x84:0x86], 0x8664)
	binary.LittleEndian.PutUint16(data[0x94:0x96], 2)
	binary.LittleEndian.PutUint16(data[0x98:0x9a], 0x20b)
	return data
}

// FixturePackage builds a valid OHNOPK01 container with minimal x64 PE fixtures.
func FixturePackage(version string) []byte {
	if version == "" {
		version = "0.2.0"
	}
	files := make(map[string][]byte, len(PackageFiles))
	for i, name := range PackageFiles {
		if i < 4 {
			files[name] = FixtureExe()
		} else {
			files[name] = []byte("fixture license\n")
		}
	}
	pkg, err := BuildPackage(version, files)
	if err != nil {
		panic(err)
	}
	return pkg
}

func TestPackageRoundtripAndBounds(t *testing.T) {
	data := FixturePackage("0.2.0")
	parsed, err := ParsePackage(data)
	if err != nil {
		t.Fatalf("ParsePackage failed: %v", err)
	}
	if parsed.Version != "0.2.0" {
		t.Fatalf("unexpected version %q", parsed.Version)
	}
	wantExe := FixtureExe()
	for i := 0; i < 4; i++ {
		r := parsed.Offsets[i]
		if !bytes.Equal(data[r.Offset:r.Offset+r.Size], wantExe) {
			t.Fatalf("payload %d mismatch", i)
		}
	}
	// Trailing/truncated/corrupt header cases.
	badCases := [][]byte{
		append(append([]byte{}, data...), 'x'),
		data[:len(data)-1],
		bytes.Repeat([]byte{'x'}, 1024),
	}
	b1 := append([]byte{}, data...)
	b1[8], b1[9] = 0xff, 0xff
	badCases = append(badCases, b1)
	b2 := append([]byte{}, data...)
	b2[10], b2[11] = 5, 0
	badCases = append(badCases, b2)
	for i, bad := range badCases {
		if _, err := ParsePackage(bad); err == nil {
			t.Fatalf("expected error on badCases[%d]", i)
		}
	}

	// Every truncation.
	for end := 0; end < len(data); end++ {
		if _, err := ParsePackage(data[:end]); err == nil {
			t.Fatalf("expected error on truncation at %d", end)
		}
	}

	// Length overflows.
	for idx := 0; idx < 6; idx++ {
		for _, sz := range []uint64{0, ^uint64(0), 1 << 32, 268435457} {
			bad := append([]byte{}, data...)
			binary.LittleEndian.PutUint64(bad[12+idx*8:20+idx*8], sz)
			if _, err := ParsePackage(bad); err == nil {
				t.Fatalf("expected error for idx=%d size=%d", idx, sz)
			}
		}
	}

	// Missing files / path injection / non-x64 PE / bad versions.
	files := make(map[string][]byte, len(PackageFiles))
	for i, name := range PackageFiles {
		if i < 4 {
			files[name] = FixtureExe()
		} else {
			files[name] = []byte("license")
		}
	}
	for _, name := range PackageFiles {
		cp := make(map[string][]byte, len(files))
		for k, v := range files {
			if k != name {
				cp[k] = v
			}
		}
		if _, err := BuildPackage("0.2.0", cp); err == nil {
			t.Fatalf("expected error with missing %s", name)
		}
	}
	escape := make(map[string][]byte, len(files))
	for k, v := range files {
		escape[k] = v
	}
	escape["../escape.exe"] = escape[PackageFiles[0]]
	delete(escape, PackageFiles[0])
	if _, err := BuildPackage("0.2.0", escape); err == nil {
		t.Fatal("expected error on path traversal filename")
	}
	peMutations := []struct {
		off int
		val []byte
	}{
		{0, []byte("NO")},
		{0x3c, []byte{0xff, 0xff, 0xff, 0xff}},
		{0x84, []byte{0x4c, 0x01}}, // x86 instead of x64
		{0x98, []byte{0x0b, 0x01}}, // PE32 instead of PE32+
	}
	for _, m := range peMutations {
		exe := FixtureExe()
		copy(exe[m.off:], m.val)
		cp := make(map[string][]byte, len(files))
		for k, v := range files {
			cp[k] = v
		}
		cp[PackageFiles[0]] = exe
		if _, err := BuildPackage("0.2.0", cp); err == nil {
			t.Fatalf("expected PE rejection for offset 0x%x", m.off)
		}
	}
	for _, ver := range []string{"0.2.0/../", "01.2.3", "0.2.0\n", "中文", "0.2.0-" + strings.Repeat("x", 33)} {
		if _, err := BuildPackage(ver, files); err == nil {
			t.Fatalf("expected rejection for version %q", ver)
		}
	}
}
