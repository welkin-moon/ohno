package teacher

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	PackageMagic      = "OHNOPK01"
	PackageHeaderSize = 60 // 8 magic + 2 versionLen + 2 count + 6*8 sizes
)

// PackageFiles is the fixed ordered payload list for OHNOPK01 containers.
var PackageFiles = [6]string{
	"ohno-worker.exe",
	"ohno-request.exe",
	"ohno-maintenance.exe",
	"ohno-tun.exe",
	"sing-box-LICENSE.txt",
	"wintun-LICENSE.txt",
}

// FileRange marks a file's offset and size inside an OHNOPK01 container.
type FileRange struct {
	Offset int
	Size   int
}

// ParsedPackage holds parsed metadata and file ranges of an OHNOPK01 container.
type ParsedPackage struct {
	Version string
	Offsets [6]FileRange
}

// IsX64Executable checks whether data begins with a valid Windows x64 PE32+ header.
func IsX64Executable(data []byte) bool {
	if len(data) < 1024 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	offset := uint64(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if offset < 0x40 || offset > uint64(len(data))-26 {
		return false
	}
	off := int(offset)
	return bytes.Equal(data[off:off+4], []byte{'P', 'E', 0, 0}) &&
		binary.LittleEndian.Uint16(data[off+4:off+6]) == 0x8664 &&
		binary.LittleEndian.Uint16(data[off+20:off+22]) >= 2 &&
		binary.LittleEndian.Uint16(data[off+24:off+26]) == 0x20b
}

// ParsePackage validates the fixed-layout OHNOPK01 container format and x64 PE headers.
func ParsePackage(data []byte) (ParsedPackage, error) {
	if len(data) < 1024 || int64(len(data)) > MaxPackageSize {
		return ParsedPackage{}, errors.New("invalid package size")
	}
	if string(data[:8]) != PackageMagic {
		return ParsedPackage{}, errors.New("invalid package header")
	}
	versionSize := int(binary.LittleEndian.Uint16(data[8:10]))
	count := int(binary.LittleEndian.Uint16(data[10:12]))
	if count != len(PackageFiles) || versionSize < 5 || versionSize > 53 {
		return ParsedPackage{}, errors.New("invalid package header")
	}
	start := PackageHeaderSize + versionSize
	if start > len(data) {
		return ParsedPackage{}, errors.New("invalid package header")
	}
	version := string(data[PackageHeaderSize:start])
	if !VersionRegexp.MatchString(version) {
		return ParsedPackage{}, errors.New("invalid package version")
	}
	var sizes [6]uint64
	var total uint64 = uint64(start)
	for i := range sizes {
		sz := binary.LittleEndian.Uint64(data[12+i*8 : 20+i*8])
		if sz < 1 || sz > uint64(MaxPackageSize) {
			return ParsedPackage{}, errors.New("invalid package lengths or trailing bytes")
		}
		if sz > uint64(len(data))-total {
			return ParsedPackage{}, errors.New("invalid package lengths or trailing bytes")
		}
		total += sz
		sizes[i] = sz
	}
	if total != uint64(len(data)) {
		return ParsedPackage{}, errors.New("invalid package lengths or trailing bytes")
	}
	var offsets [6]FileRange
	pos := start
	for i, sz := range sizes {
		n := int(sz)
		if i < 4 && !IsX64Executable(data[pos:pos+n]) {
			return ParsedPackage{}, errors.New("payload executable is not x64 PE32+")
		}
		if i >= 4 && n > 1024*1024 {
			return ParsedPackage{}, errors.New("license file too large")
		}
		offsets[i] = FileRange{Offset: pos, Size: n}
		pos += n
	}
	return ParsedPackage{Version: version, Offsets: offsets}, nil
}

// BuildPackage creates an unsigned fixed-layout OHNOPK01 container.
func BuildPackage(version string, files map[string][]byte) ([]byte, error) {
	if !VersionRegexp.MatchString(version) || len(files) != len(PackageFiles) {
		return nil, errors.New("invalid package version or fixed file set")
	}
	total := int64(PackageHeaderSize + len(version))
	for _, name := range PackageFiles {
		content, ok := files[name]
		if !ok || content == nil {
			return nil, errors.New("invalid package version or fixed file set")
		}
		total += int64(len(content))
		if total > MaxPackageSize {
			return nil, errors.New("package too large")
		}
	}
	buf := make([]byte, 0, total)
	var header [PackageHeaderSize]byte
	copy(header[:8], PackageMagic)
	binary.LittleEndian.PutUint16(header[8:10], uint16(len(version)))
	binary.LittleEndian.PutUint16(header[10:12], uint16(len(PackageFiles)))
	for i, name := range PackageFiles {
		binary.LittleEndian.PutUint64(header[12+i*8:20+i*8], uint64(len(files[name])))
	}
	buf = append(buf, header[:]...)
	buf = append(buf, version...)
	for _, name := range PackageFiles {
		buf = append(buf, files[name]...)
	}
	if _, err := ParsePackage(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
