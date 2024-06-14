package allowlist

import (
	"context"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type allowlistPlugin struct {
	Next    plugin.Handler
	Domains []string
}

func (a *allowlistPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	question := r.Question[0].Name
	for _, domain := range a.Domains {
		if strings.HasSuffix(question, domain+".") {
			return plugin.NextOrFailure(a.Name(), a.Next, ctx, w, r)
		}
	}
	return dns.RcodeNameError, nil
}

func (a *allowlistPlugin) Name() string {
	return "allowlist"
}

func parse(c *caddy.Controller) (*allowlistPlugin, error) {
	allowlist := &allowlistPlugin{}
	for c.Next() {
		if c.NextBlock() {
			for {
				if c.Val() == "domain" {
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					allowlist.Domains = append(allowlist.Domains, c.Val())
				}
				if !c.Next() {
					break
				}
			}
		}
	}
	return allowlist, nil
}

func setup(c *caddy.Controller) error {
	allowlist, err := parse(c)
	if err != nil {
		return plugin.Error("allowlist", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		allowlist.Next = next
		return allowlist
	})

	return nil
}

func init() {
	plugin.Register("allowlist", setup)
}
