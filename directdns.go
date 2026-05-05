package directdns

import (
    "context"
    "net"
    "strings"
    "time"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/coredns/coredns/request"

    "github.com/miekg/dns"
)

type DirectDNS struct {
    Next  plugin.Handler
    Zones []string
}

type captureWriter struct {
    dns.ResponseWriter
    msg *dns.Msg
}

func (cw *captureWriter) WriteMsg(msg *dns.Msg) error {
    cw.msg = msg.Copy()
    return nil
}

var _ plugin.Handler = &DirectDNS{}

func (directdns *DirectDNS) Name() string { return "directdns" }

func (directdns *DirectDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    state := request.Request{W: w, Req: r}
    queryName := state.Name()
    log.Infof("[directdns] ServeDNS: query=%s, zones=%v", queryName, directdns.Zones)

    zone := directdns.matchZone(queryName)
    if zone != "" {
        log.Infof("[directdns] direct match: query=%s, zone=%s", queryName, zone)
        return directdns.handleDirectQuery(ctx, r, w, zone, queryName)
    }

    log.Infof("[directdns] no direct match, trying indirect for: %s", queryName)
    return directdns.handleIndirectQuery(ctx, w, r)
}

func (directdns *DirectDNS) handleDirectQuery(ctx context.Context, r *dns.Msg, w dns.ResponseWriter, zone, queryName string) (int, error) {
    log.Infof("[directdns] handleDirectQuery: query=%s, zone=%s", queryName, zone)
    subdomain := trimZone(queryName, zone)
    log.Infof("[directdns] subdomain: %q", subdomain)
    if subdomain == "" {
        return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
    }
    ipv6 := decodeIPv6(subdomain)
    log.Infof("[directdns] decoded IPv6: %s", ipv6)
    if ipv6 == "" {
        return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
    }

    resp, err := forwardToNode(r, ipv6)
    if err != nil || resp == nil {
        log.Infof("[directdns] forward failed: %v, falling back", err)
        return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
    }

    resp.SetReply(r)
    resp.Authoritative = true
    w.WriteMsg(resp)
    return dns.RcodeSuccess, nil
}

func (directdns *DirectDNS) handleIndirectQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    log.Infof("[directdns] handleIndirectQuery called")
    if directdns.Next == nil {
        log.Infof("[directdns] Next is nil, returning")
        return plugin.NextOrFailure(directdns.Name(), directdns.Next, ctx, w, r)
    }

    cw := &captureWriter{ResponseWriter: w}
    rcode, err := directdns.Next.ServeDNS(ctx, cw, r)
    if err != nil {
        log.Infof("[directdns] Next returned error: %v", err)
        return rcode, err
    }
    resp := cw.msg
    if resp == nil {
        log.Infof("[directdns] Next returned nil response")
        return rcode, nil
    }

    log.Infof("[directdns] indirect response answer: %v", resp.Answer)
    newAnswer, modified := directdns.rewriteCNAMEs(resp, r)
    if modified {
        log.Infof("[directdns] CNAME rewritten, new answer: %v", newAnswer)
        newResp := new(dns.Msg)
        newResp.SetReply(r)
        newResp.Authoritative = resp.Authoritative
        newResp.Answer = newAnswer
        newResp.Ns = resp.Ns
        newResp.Extra = resp.Extra
        newResp.Rcode = resp.Rcode
        w.WriteMsg(newResp)
        return dns.RcodeSuccess, nil
    }

    log.Infof("[directdns] no CNAME rewrite, passing through")
    w.WriteMsg(resp)
    return rcode, nil
}

func (directdns *DirectDNS) rewriteCNAMEs(originalResp *dns.Msg, r *dns.Msg) ([]dns.RR, bool) {
    var newAnswer []dns.RR
    found := false

    for i, rr := range originalResp.Answer {
        if found {
            break
        }
        newAnswer = append(newAnswer, rr)
        cname, ok := rr.(*dns.CNAME)
        if !ok {
            continue
        }

        log.Infof("[directdns] checking CNAME target: %s", cname.Target)
        targetZone := directdns.matchZone(cname.Target)
        if targetZone == "" {
            log.Infof("[directdns] CNAME target not in our zones")
            continue
        }

        subdomain := trimZone(cname.Target, targetZone)
        ipv6 := decodeIPv6(subdomain)
        if ipv6 == "" {
            log.Infof("[directdns] could not decode IPv6 from subdomain: %s", subdomain)
            continue
        }

        log.Infof("[directdns] querying IPv6 %s for CNAME target %s", ipv6, cname.Target)
        ipv6Resp, err := forwardToNodeWithName(r, ipv6, cname.Target)
        if err != nil || ipv6Resp == nil {
            log.Infof("[directdns] IPv6 query failed: %v", err)
            continue
        }

        found = true
        newAnswer = newAnswer[:i+1]
        newAnswer = append(newAnswer, ipv6Resp.Answer...)
    }

    return newAnswer, found
}

func (directdns *DirectDNS) matchZone(queryName string) string {
    for _, zone := range directdns.Zones {
        if plugin.Name(zone).Matches(queryName) {
            return zone
        }
    }
    return ""
}

func trimZone(queryName, zone string) string {
    queryName = dns.Fqdn(queryName)
    zone = dns.Fqdn(zone)
    if !strings.HasSuffix(queryName, zone) {
        return ""
    }
    return strings.TrimSuffix(queryName, zone)
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
    return resp, err
}

func forwardToNodeWithName(req *dns.Msg, ipv6 string, name string) (*dns.Msg, error) {
    newReq := req.Copy()
    if len(newReq.Question) > 0 {
        newReq.Question[0].Name = dns.Fqdn(name)
    }

    c := &dns.Client{
        Net:     "udp",
        Timeout: 2 * time.Second,
    }

    addr := "[" + ipv6 + "]:53"
    resp, _, err := c.Exchange(newReq, addr)
    return resp, err
}
