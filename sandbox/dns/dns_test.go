package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/pkg/errors"
)

func TestLookupA(t *testing.T) {
	tests := []struct {
		name               string
		records            map[string]net.IP
		req                string
		expIPs             []net.IP
		lookupExternalHost func(string) ([]string, error)
	}{
		{
			name: "internal hostname",
			records: map[string]net.IP{
				"host": net.IPv4(8, 8, 8, 8),
			},
			req: "host.",
			expIPs: []net.IP{
				net.IPv4(8, 8, 8, 8),
			},
		},
		{
			name: "internal with tld",
			records: map[string]net.IP{
				"dev.kelda": net.IPv4(8, 8, 8, 8),
			},
			req: "dev.kelda.",
			expIPs: []net.IP{
				net.IPv4(8, 8, 8, 8),
			},
		},
		{
			name: "external hostname",
			records: map[string]net.IP{
				"does-not-match": net.IPv4(8, 8, 8, 8),
			},
			req: "google.com.",
			expIPs: []net.IP{
				net.IPv4(9, 9, 9, 9),
			},
			lookupExternalHost: func(host string) ([]string, error) {
				if host == "google.com" {
					return []string{"9.9.9.9"}, nil
				}
				return nil, errors.New("unknown host")
			},
		},
		{
			name: "external hostname with multiple IPs",
			records: map[string]net.IP{
				"does-not-match": net.IPv4(8, 8, 8, 8),
			},
			req: "google.com.",
			expIPs: []net.IP{
				net.IPv4(9, 9, 9, 9),
				net.IPv4(10, 10, 10, 10),
			},
			lookupExternalHost: func(host string) ([]string, error) {
				if host == "google.com" {
					return []string{"9.9.9.9", "10.10.10.10"}, nil
				}
				return nil, errors.New("unknown host")
			},
		},
	}

	for _, test := range tests {
		lookupHost = test.lookupExternalHost
		tbl := dnsTable{records: test.records}
		assert.Equal(t, test.expIPs, tbl.lookupA(test.req), test.name)
	}
}
