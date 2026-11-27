package teacher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	InstallerMagicV1  = "OHNOBT01"
	InstallerMagicV2  = "OHNOBT02"
	TrailerV1Size     = 16
	TrailerV2Size     = 20
	MaxOriginLen      = 1024
	MaxCertLen        = 16384
	MaxInstallerBytes = 256 * 1024 * 1024
)

var HostnameRegexp = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func isValidHostname(host string) bool {
	return len(host) >= 1 && len(host) <= 253 && HostnameRegexp.MatchString(host)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			return false
		}
	}
	return true
}

// EnrollmentOrigin formats a canonical https://<host>:<port> origin, bracketing IPv6 addresses.
func EnrollmentOrigin(host string, port int) (string, error) {
	if !isASCII(host) || port < 1 || port > 65535 {
		return "", errors.New("invalid teacher host or port")
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		if addr.Is6() {
			return "https://[" + addr.String() + "]:" + strconv.Itoa(port), nil
		}
		return "https://" + addr.String() + ":" + strconv.Itoa(port), nil
	}
	lower := strings.ToLower(host)
	if !isValidHostname(lower) {
		return "", errors.New("invalid teacher hostname")
	}
	return "https://" + lower + ":" + strconv.Itoa(port), nil
}

// ValidateOrigin validates a standalone HTTPS origin matching the native Windows installer.
func ValidateOrigin(serverURL string) error {
	if len(serverURL) == 0 || len(serverURL) > MaxOriginLen || !strings.HasPrefix(serverURL, "https://") {
		return errors.New("invalid teacher origin")
	}
	for i := 0; i < len(serverURL); i++ {
		c := serverURL[i]
		if c < 33 || c > 126 || c == '\\' || c == '?' || c == '#' {
			return errors.New("invalid teacher origin")
		}
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("teacher origin must be a standalone HTTPS origin")
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return errors.New("teacher origin requires an explicit port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return errors.New("invalid teacher port")
	}
	_, err = EnrollmentOrigin(host, port)
	return err
}

// BuildSchoolInstaller appends a v1 (OHNOBT01) or v2 (OHNOBT02) trust trailer to setupExe.
func BuildSchoolInstaller(setupExe []byte, serverURL string, certificatePEM []byte, releasePublicKey string) ([]byte, error) {
	if len(setupExe) < 1024 || len(setupExe) > MaxInstallerBytes {
		return nil, errors.New("invalid base installer")
	}
	if err := ValidateOrigin(serverURL); err != nil {
		return nil, err
	}
	if len(certificatePEM) < 100 || len(certificatePEM) > MaxCertLen ||
		!bytes.HasPrefix(certificatePEM, []byte("-----BEGIN CERTIFICATE-----")) ||
		!bytes.Contains(certificatePEM, []byte("-----END CERTIFICATE-----")) ||
		bytes.IndexByte(certificatePEM, 0) >= 0 ||
		bytes.Contains(certificatePEM, []byte("PRIVATE KEY")) {
		return nil, errors.New("invalid public certificate")
	}
	urlBytes := []byte(serverURL)
	if releasePublicKey != "" {
		if _, err := ParsePinnedPublicKey(releasePublicKey); err != nil {
			return nil, errors.New("invalid pinned release public key")
		}
		keyBytes := []byte(releasePublicKey)
		out := make([]byte, 0, len(setupExe)+len(urlBytes)+len(certificatePEM)+len(keyBytes)+TrailerV2Size)
		out = append(out, setupExe...)
		out = append(out, urlBytes...)
		out = append(out, certificatePEM...)
		out = append(out, keyBytes...)
		var trailer [TrailerV2Size]byte
		binary.LittleEndian.PutUint32(trailer[0:4], uint32(len(urlBytes)))
		binary.LittleEndian.PutUint32(trailer[4:8], uint32(len(certificatePEM)))
		binary.LittleEndian.PutUint32(trailer[8:12], uint32(len(keyBytes)))
		copy(trailer[12:20], InstallerMagicV2)
		out = append(out, trailer[:]...)
		return out, nil
	}
	out := make([]byte, 0, len(setupExe)+len(urlBytes)+len(certificatePEM)+TrailerV1Size)
	out = append(out, setupExe...)
	out = append(out, urlBytes...)
	out = append(out, certificatePEM...)
	var trailer [TrailerV1Size]byte
	binary.LittleEndian.PutUint32(trailer[0:4], uint32(len(urlBytes)))
	binary.LittleEndian.PutUint32(trailer[4:8], uint32(len(certificatePEM)))
	copy(trailer[8:16], InstallerMagicV1)
	out = append(out, trailer[:]...)
	return out, nil
}

// GetSchoolConfiguration extracts origin and public certificate from a school installer.
func GetSchoolConfiguration(installer []byte) (string, []byte, error) {
	origin, cert, _, err := GetSchoolTrust(installer)
	return origin, cert, err
}

// GetSchoolTrust extracts origin, public certificate, and optional v2 pinned release public key.
func GetSchoolTrust(installer []byte) (string, []byte, string, error) {
	if len(installer) >= TrailerV2Size && string(installer[len(installer)-8:]) == InstallerMagicV2 {
		t := installer[len(installer)-TrailerV2Size:]
		urlSize := int(binary.LittleEndian.Uint32(t[0:4]))
		certSize := int(binary.LittleEndian.Uint32(t[4:8]))
		keySize := int(binary.LittleEndian.Uint32(t[8:12]))
		if urlSize < 1 || urlSize > MaxOriginLen || certSize < 100 || certSize > MaxCertLen || keySize != 130 {
			return "", nil, "", errors.New("invalid release trust trailer")
		}
		start := len(installer) - TrailerV2Size - urlSize - certSize - keySize
		if start < 1024 {
			return "", nil, "", errors.New("truncated trusted installer")
		}
		origin := string(installer[start : start+urlSize])
		cert := append([]byte(nil), installer[start+urlSize:start+urlSize+certSize]...)
		key := string(installer[start+urlSize+certSize : len(installer)-TrailerV2Size])
		rebuilt, err := BuildSchoolInstaller(installer[:start], origin, cert, key)
		if err != nil || !bytes.Equal(rebuilt, installer) {
			return "", nil, "", errors.New("noncanonical release trust trailer")
		}
		return origin, cert, key, nil
	}
	if len(installer) < TrailerV1Size {
		return "", nil, "", errors.New("missing trailer")
	}
	t := installer[len(installer)-TrailerV1Size:]
	urlSize := int(binary.LittleEndian.Uint32(t[0:4]))
	certSize := int(binary.LittleEndian.Uint32(t[4:8]))
	if string(t[8:16]) != InstallerMagicV1 || urlSize < 1 || urlSize > MaxOriginLen || certSize < 100 || certSize > MaxCertLen {
		return "", nil, "", errors.New("missing enrollment data")
	}
	start := len(installer) - TrailerV1Size - urlSize - certSize
	if start < 1024 {
		return "", nil, "", errors.New("truncated installer")
	}
	origin := string(installer[start : start+urlSize])
	cert := append([]byte(nil), installer[start+urlSize:start+urlSize+certSize]...)
	rebuilt, err := BuildSchoolInstaller(installer[:start], origin, cert, "")
	if err != nil || !bytes.Equal(rebuilt, installer) {
		return "", nil, "", errors.New("noncanonical enrollment trailer")
	}
	return origin, cert, "", nil
}
