package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/zkmkarlsruhe/filterdns-client/internal/config"
)

// Proxy is a local DNS proxy that forwards queries to FilterDNS or split DNS servers
type Proxy struct {
	config     *config.Config
	server     *dns.Server
	dohClient  *DoHClient
	forwarders *ForwarderMatcher
	cache      *Cache
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc

	// Stats
	queriesTotal   int64
	queriesBlocked int64
}

// NewProxy creates a new DNS proxy
func NewProxy(cfg *config.Config) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		config:     cfg,
		dohClient:  NewDoHClient(cfg.ServerURL, cfg.Profile),
		forwarders: NewForwarderMatcher(cfg.Forwarders),
		cache:      NewCache(5*time.Minute, 10000),
		ctx:        ctx,
		cancel:     cancel,
	}

	return p
}

// Start starts the DNS proxy server
func (p *Proxy) Start() error {
	p.server = &dns.Server{
		Addr:    "127.0.0.1:53",
		Net:     "udp",
		Handler: dns.HandlerFunc(p.handleQuery),
	}

	// Also listen on TCP
	go func() {
		tcpServer := &dns.Server{
			Addr:    "127.0.0.1:53",
			Net:     "tcp",
			Handler: dns.HandlerFunc(p.handleQuery),
		}
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP server error: %v", err)
		}
	}()

	log.Printf("DNS proxy listening on 127.0.0.1:53")
	return p.server.ListenAndServe()
}

// Stop stops the DNS proxy server
func (p *Proxy) Stop() {
	p.cancel()
	if p.server != nil {
		p.server.Shutdown()
	}
}

// handleQuery processes incoming DNS queries
func (p *Proxy) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	p.queriesTotal++

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	// Check cache first
	if cached := p.cache.Get(qname, q.Qtype); cached != nil {
		cached.Id = r.Id
		w.WriteMsg(cached)
		return
	}

	// Check if this domain should be forwarded to a split DNS server
	if forwarder := p.forwarders.Match(qname); forwarder != "" {
		p.forwardToServer(w, r, forwarder)
		return
	}

	// Forward to FilterDNS via DoH
	p.forwardToDoH(w, r)
}

// forwardToDoH forwards the query to FilterDNS via DNS-over-HTTPS
func (p *Proxy) forwardToDoH(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()

	// Get password if needed
	password, _ := config.GetPassword(p.config.Profile)

	resp, err := p.dohClient.Query(ctx, r, password)
	if err != nil {
		log.Printf("DoH query failed: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	// Cache the response
	if len(r.Question) > 0 {
		q := r.Question[0]
		p.cache.Set(strings.ToLower(q.Name), q.Qtype, resp)
	}

	// Check if response indicates blocking
	if isBlockedResponse(resp) {
		p.queriesBlocked++
	}

	w.WriteMsg(resp)
}

// forwardToServer forwards the query to a traditional DNS server
func (p *Proxy) forwardToServer(w dns.ResponseWriter, r *dns.Msg, server string) {
	// Ensure server has a port
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	resp, _, err := client.Exchange(r, server)
	if err != nil {
		log.Printf("Forward to %s failed: %v", server, err)
		dns.HandleFailed(w, r)
		return
	}

	// Cache the response
	if len(r.Question) > 0 {
		q := r.Question[0]
		p.cache.Set(strings.ToLower(q.Name), q.Qtype, resp)
	}

	w.WriteMsg(resp)
}

// UpdateForwarders updates the split DNS forwarders
func (p *Proxy) UpdateForwarders(forwarders []config.Forwarder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forwarders = NewForwarderMatcher(forwarders)
}

// GetStats returns current proxy statistics
func (p *Proxy) GetStats() (total, blocked int64) {
	return p.queriesTotal, p.queriesBlocked
}

// isBlockedResponse checks if a DNS response indicates a blocked domain
func isBlockedResponse(resp *dns.Msg) bool {
	if resp.Rcode == dns.RcodeNameError {
		return true
	}

	// Check for 0.0.0.0 or :: responses (common blocking indicators)
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if rr.A.Equal(net.IPv4zero) {
				return true
			}
		case *dns.AAAA:
			if rr.AAAA.Equal(net.IPv6zero) {
				return true
			}
		}
	}

	return false
}
