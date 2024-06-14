package allowlist

import (
	"context"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestAllowlistPlugin(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		query    string
		expected int
	}{
		{
			name: "Allowed domain",
			config: `
allowlist {
    domain example.com
    domain example.org
}
`,
			query:    "example.com.",
			expected: dns.RcodeSuccess,
		},
		{
			name: "Allowed subdomain",
			config: `
allowlist {
    domain example.com
    domain example.org
}
`,
			query:    "subdomain.example.com.",
			expected: dns.RcodeSuccess,
		},
		{
			name: "Disallowed domain",
			config: `
allowlist {
    domain example.com
    domain example.org
}
`,
			query:    "example.net.",
			expected: dns.RcodeNameError,
		},
		{
			name: "Disallowed subdomain",
			config: `
allowlist {
    domain example.com
    domain example.org
}
`,
			query:    "subdomain.example.net.",
			expected: dns.RcodeNameError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			allowlist, err := parse(c)
			if err != nil {
				t.Fatalf("Error parsing config: %v", err)
			}

			req := new(dns.Msg)
			req.SetQuestion(tc.query, dns.TypeA)

			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			ctx := context.TODO()
			next := test.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
				return dns.RcodeSuccess, nil
			})

			allowlist.Next = next

			code, err := allowlist.ServeDNS(ctx, rec, req)
			if err != nil {
				t.Fatalf("Error serving DNS: %v", err)
			}

			if code != tc.expected {
				t.Errorf("Expected response code %d, got %d", tc.expected, code)
			}
		})
	}
}
