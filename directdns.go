package directdns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type DirectDNS struct {
	Next  plugin.Handler
	Zones []string
}

var _ plugin.Handler = &DirectDNS{}

func (directdns *DirectDNS) Name() string { return "directdns" }
func (directdns *DirectDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	queryName := state.Name()

	zone := directdns.matchZone(queryName)
	if zone == "" {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	subdomain := trimZone(queryName, zone)
	if subdomain == "" {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	ipv6 := decodeIPv6(subdomain)
	if ipv6 == "" {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	resp, err := forwardToNode(r, ipv6)
	if err != nil || resp == nil {
		return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
	}

	resp.SetReply(r)
	resp.Authoritative = true

	_ = w.WriteMsg(resp)
	return dns.RcodeSuccess, nil
}

func normalizeZone(zone string) string {
	// dns://example.com.:53
	if strings.HasPrefix(zone, "dns://") {
		zone = strings.TrimPrefix(zone, "dns://")
		if i := strings.Index(zone, ":"); i != -1 {
			zone = zone[:i]
		}
	}
	return dns.Fqdn(zone)
}

func (directdns *DirectDNS) matchZone(query_name string) string {
	for _, raw_zone := range directdns.Zones {
		zone := normalizeZone(raw_zone)
		if plugin.Name(zone).Matches(query_name) {
			return dns.Fqdn(zone)
		}
	}
	return ""
}

func trimZone(query_name, zone string) string {
	query_name = dns.Fqdn(query_name)
	zone = dns.Fqdn(zone)
	if !strings.HasSuffix(query_name, zone) {
		return ""
	}
	return strings.TrimSuffix(query_name, zone)
}

func lastLabel(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func decodeIPv6(subdomain string) string {
	label := lastLabel(subdomain)
	ip := strings.ReplaceAll(label, "-", ":")
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func forwardToNode(req *dns.Msg, ipv6 string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	addr := "[" + ipv6 + "]:53"
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
