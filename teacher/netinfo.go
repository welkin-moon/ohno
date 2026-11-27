package teacher

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range []string{
		"ohno", "wintun", "docker", "veth", "br-", "virbr",
		"wsl", "vethernet", "hyper-v", "vmware", "vmnet", "vbox", "virtualbox",
		"tailscale", "zerotier", "wireguard", "tun", "tap", "loopback",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isRFC1918(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	if b[0] == 10 {
		return true
	}
	if b[0] == 172 && b[1] >= 16 && b[1] <= 31 {
		return true
	}
	if b[0] == 192 && b[1] == 168 {
		return true
	}
	return false
}

func isBenchmarkRange(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	// 198.18.0.0/15 is used by ohno-tun and synthetic benchmarks.
	return b[0] == 198 && (b[1] == 18 || b[1] == 19)
}

// DetectLANIPs returns active local IPv4 addresses suitable for LAN student enrollment,
// ordered with physical RFC1918 addresses first.
func DetectLANIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	type candidate struct {
		ip       string
		priority int
	}
	seen := map[string]int{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		virt := isVirtualInterfaceName(iface.Name)
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(v4)
			if !ok || !addr.Is4() {
				continue
			}
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
				addr.IsMulticast() || addr.IsUnspecified() || isBenchmarkRange(addr) {
				continue
			}
			prio := 3
			if !virt && isRFC1918(addr) {
				prio = 0
			} else if !virt {
				prio = 1
			} else if isRFC1918(addr) {
				prio = 2
			}
			s := addr.String()
			if prev, exists := seen[s]; !exists || prio < prev {
				seen[s] = prio
			}
		}
	}
	items := make([]candidate, 0, len(seen))
	for ip, prio := range seen {
		items = append(items, candidate{ip: ip, priority: prio})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].priority != items[j].priority {
			return items[i].priority < items[j].priority
		}
		return items[i].ip < items[j].ip
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ip
	}
	return out
}

// CertificateFingerprint computes the short uppercase SHA-256 fingerprint (XXXX-XXXX-XXXX-XXXX)
// of a PEM-encoded X.509 certificate, matching the Windows setup wizard display.
func CertificateFingerprint(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X-%02X%02X",
		sum[0], sum[1], sum[2], sum[3], sum[4], sum[5], sum[6], sum[7])
}

// CertCoversIPs returns true when certPEM parses as a valid X.509 certificate and its IP SANs
// include every IP string in ips.
func CertCoversIPs(certPEM []byte, ips []string) bool {
	if len(ips) == 0 {
		return true
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		target := net.IP(addr.AsSlice())
		found := false
		for _, ip := range cert.IPAddresses {
			if ip.Equal(target) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// CertSANSummary returns the DNS and IP Subject Alternative Names embedded in certPEM.
func CertSANSummary(certPEM []byte) (dnsNames []string, ipAddrs []string) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil
	}
	dnsNames = append(dnsNames, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		ipAddrs = append(ipAddrs, ip.String())
	}
	return dnsNames, ipAddrs
}
