package crypto

import (
	"net"
	"strings"
)

// isValidDomain ensures the domain resolves to a legitimate public address, not a local
// or internal one. Defends against SSRF by blocking RFC1918, loopback, link-local, ULA,
// multicast, and unspecified ranges for both IPv4 and IPv6.
func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}
	// Reject syntactically suspicious values before DNS resolution.
	if strings.ContainsAny(domain, " /\\?#@") {
		return false
	}
	// Must contain a dot (rules out bare "localhost" and single-label names).
	if !strings.Contains(domain, ".") {
		return false
	}

	// If the domain is a bare IP literal, validate it directly.
	if ip := net.ParseIP(domain); ip != nil {
		return isPublicIP(ip)
	}

	// Resolve the domain and check all returned addresses.
	addrs, err := net.LookupHost(domain)
	if err != nil {
		// If resolution fails we cannot confirm it is safe — reject.
		return false
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || !isPublicIP(ip) {
			return false
		}
	}
	return len(addrs) > 0
}

// isPublicIP returns true only for globally routable unicast addresses,
// blocking loopback, private (RFC1918/RFC4193), link-local, multicast, and unspecified.
func isPublicIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}
