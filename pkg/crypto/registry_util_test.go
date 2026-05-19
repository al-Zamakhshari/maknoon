package crypto

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// public
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		// loopback
		{"127.0.0.1", false},
		{"::1", false},
		// RFC1918
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.255.255", false},
		// link-local unicast
		{"169.254.1.1", false},
		{"fe80::1", false},
		// IPv6 ULA (fc00::/7 covers both fc and fd prefixes)
		{"fc00::1", false},
		{"fd12:3456:789a::1", false},
		// multicast
		{"224.0.0.1", false},
		{"239.255.255.255", false},
		{"ff02::1", false},
		// unspecified
		{"0.0.0.0", false},
		{"::", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("test setup: net.ParseIP(%q) returned nil", tt.ip)
		}
		got := isPublicIP(ip)
		if got != tt.want {
			t.Errorf("isPublicIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsValidDomainIPLiterals(t *testing.T) {
	// These are IP literals so no DNS resolution is needed — hermetic.
	tests := []struct {
		domain string
		want   bool
		desc   string
	}{
		{"1.1.1.1", true, "public IPv4"},
		{"8.8.8.8", true, "public IPv4"},
		{"127.0.0.1", false, "loopback"},
		{"::1", false, "IPv6 loopback"},
		{"10.0.0.1", false, "RFC1918 10.x"},
		{"172.16.0.1", false, "RFC1918 172.16 low"},
		{"172.31.255.255", false, "RFC1918 172.31 high"},
		{"192.168.1.1", false, "RFC1918 192.168"},
		{"169.254.1.1", false, "IPv4 link-local"},
		{"fe80::1", false, "IPv6 link-local"},
		{"fc00::1", false, "IPv6 ULA fc00"},
		{"fd00::1", false, "IPv6 ULA fd00"},
		{"224.0.0.1", false, "IPv4 multicast"},
		{"ff02::1", false, "IPv6 multicast"},
		{"0.0.0.0", false, "unspecified"},
		{"::", false, "IPv6 unspecified"},
		// syntax checks (no DNS resolution)
		{"", false, "empty"},
		{"bad domain", false, "space in domain"},
		{"evil/path", false, "slash in domain"},
		{"nodot", false, "no dot — single label, no DNS → rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := isValidDomain(tt.domain)
			if got != tt.want {
				t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
