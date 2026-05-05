package directdns

import (
    "github.com/coredns/caddy"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/miekg/dns"
)

func init() { plugin.Register("directdns", setup) }

func setup(c *caddy.Controller) error {
    d := &DirectDNS{}
    for c.Next() {
        args := c.RemainingArgs()
        if len(args) == 0 {
            return c.ArgErr()
        }
        for _, zone := range args {
            normalized := dns.Fqdn(zone)
            log.Debugf("[directdns] adding zone: %s (from %s)", normalized, zone)
            d.Zones = append(d.Zones, normalized)
        }
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        d.Next = next
        log.Debugf("[directdns] plugin instance created, Next is nil: %v", next == nil)
        return d
    })

    return nil
}
