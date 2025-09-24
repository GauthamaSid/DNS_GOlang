package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// Redis client for caching DNS records
var redisClient *redis.Client

// Cache expiration time for records in Redis
const redisCacheTTL = 5 * time.Minute

// Default upstream DNS server
const defaultUpstreamDNSServer = "8.8.8.8:53"

// Predefined static DNS records for test
var staticRecords = map[string]map[uint16][]string{
	"example.com.": {
		dns.TypeA:    {"93.184.216.34"},
		dns.TypeAAAA: {"2606:2800:220:1:248:1893:25c8:1946"},
		dns.TypeMX:   {"10 mail.example.com."},
		dns.TypeTXT:  {"\"v=spf1 include:_spf.example.com ~all\""},
		dns.TypeNS:   {"ns1.example.com.", "ns2.example.com."},
		dns.TypePTR:  {"ptr.example.com."},
	},
	"sub.example.com.": {
		dns.TypeA: {"192.0.2.1"},
	},
	"mail.example.com.": {
		dns.TypeA: {"198.51.100.1"},
	},
	"www.example.com.": {
		dns.TypeCNAME: {"example.com."},
	},
	"example.org.": {
		dns.TypeA:    {"192.0.2.0"},
		dns.TypeTXT:  {"\"Another example domain\""},
		dns.TypeSRV:  {"10 0 80 http.example.org."},
	},
	"service._tcp.example.com.": {
		dns.TypeSRV: {"10 0 80 server1.example.com."},
	},
	"server1.example.com.": {
		dns.TypeA: {"192.0.2.10"},
	},
	"1.0.0.127.in-addr.arpa.": { // PTR for 127.0.0.1
		dns.TypePTR: {"localhost."},
	},
}

// DNSServerHandler implements the dns.Handler interface
type DNSServerHandler struct {
	upstreamDNSServer string
	// Mutex to protect cache operations if not using Redis for everything
	// For this example, Redis handles concurrency
	mu sync.RWMutex
}

// NewDNSServerHandler creates a new DNSServerHandler
func NewDNSServerHandler(upstream string) *DNSServerHandler {
	return &DNSServerHandler{
		upstreamDNSServer: upstream,
	}
}

// ServeDNS handles incoming DNS requests
func (h *DNSServerHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx := context.Background()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false // We are acting as a recursive resolver/caching server

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name)
	qType := q.Qtype

	log.Printf("Received query for %s (Type %s) from %s\n", qName, dns.Type(qType).String(), w.RemoteAddr().String())

	// 1. Check Static Records First
	if staticData, ok := staticRecords[qName]; ok {
		if records, found := staticData[qType]; found {
			log.Printf("Found static record for %s (Type %s)\n", qName, dns.Type(qType).String())
			h.addRecordsToMsg(m, q, records, dns.ClassINET, 60, true) // Static records are authoritative for us
			w.WriteMsg(m)
			return
		}
	}

	// 2. Check Redis Cache
	cacheKey := fmt.Sprintf("%s:%d", qName, qType)
	cachedValue, err := redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		log.Printf("Found cached record for %s (Type %s)\n", qName, dns.Type(qType).String())
		records := strings.Split(cachedValue, "|")
		h.addRecordsToMsg(m, q, records, dns.ClassINET, 300, false) // Cached records might have shorter TTLs or be non-authoritative
		w.WriteMsg(m)
		return
	} else if err != redis.Nil {
		log.Printf("Error checking Redis cache: %v\n", err)
	}

	// 3. Query Upstream DNS Server
	log.Printf("Querying upstream server %s for %s (Type %s)\n", h.upstreamDNSServer, qName, dns.Type(qType).String())
	upstreamClient := new(dns.Client)
	upstreamClient.DialTimeout = 5 * time.Second
	upstreamClient.ReadTimeout = 5 * time.Second
	upstreamClient.WriteTimeout = 5 * time.Second

	upstreamMsg, _, err := upstreamClient.Exchange(r, h.upstreamDNSServer)
	if err != nil {
		log.Printf("Error querying upstream DNS server: %v\n", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	if upstreamMsg.Rcode != dns.RcodeSuccess {
		log.Printf("Upstream server returned RCODE %d for %s (Type %s)\n", upstreamMsg.Rcode, qName, dns.Type(qType).String())
		m.SetRcode(r, upstreamMsg.Rcode)
		w.WriteMsg(m)
		return
	}

	// Process upstream response
	if len(upstreamMsg.Answer) > 0 {
		m.Answer = upstreamMsg.Answer
		// Cache the upstream response
		var records []string
		for _, ans := range upstreamMsg.Answer {
			records = append(records, ans.String())
		}
		serializedRecords := strings.Join(records, "|")
		err := redisClient.Set(ctx, cacheKey, serializedRecords, redisCacheTTL).Err()
		if err != nil {
			log.Printf("Error caching response in Redis: %v\n", err)
		} else {
			log.Printf("Cached upstream response for %s (Type %s)\n", qName, dns.Type(qType).String())
		}
	} else if len(upstreamMsg.Ns) > 0 {
		// If no answer, but NS records are present, include them in the response
		// This happens for delegations
		m.Ns = upstreamMsg.Ns
	} else {
		// No records found, set NXDOMAIN if upstream indicates so, otherwise NoError with no answers
		if upstreamMsg.Rcode == dns.RcodeNameError {
			m.SetRcode(r, dns.RcodeNameError)
		}
	}

	w.WriteMsg(m)
}

func (h *DNSServerHandler) addRecordsToMsg(m *dns.Msg, q dns.Question, records []string, class uint16, ttl uint32, authoritative bool) {
	m.Authoritative = authoritative
	for _, recStr := range records {
		rr, err := dns.NewRR(recStr)
		if err != nil {
			log.Printf("Error parsing record string '%s': %v\n", recStr, err)
			continue
		}
	if rr.Header().Name == q.Name || q.Qtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeCNAME {
			rr.Header().Ttl = ttl // Override TTL for static/cached records if desired
			m.Answer = append(m.Answer, rr)
		} else {
			log.Printf("Skipping record '%s' as it does not match query %s (Type %s)\n", recStr, q.Name, dns.Type(q.Qtype).String())
		}
	}
if q.Qtype != dns.TypeCNAME {
		// Check if the answer contains a CNAME for the queried name
		for _, ans := range m.Answer {
			if cname, ok := ans.(*dns.CNAME); ok && cname.Hdr.Name == q.Name {
				log.Printf("CNAME for %s found: %s. A more advanced resolver would now follow this.", q.Name, cname.Target)
			break
			}
		}
	}
}

// setupRedis initializes the Redis client
func setupRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Replace with your Redis server address
		Password: "",               // No password by default
		DB:       0,                // Default DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Could not connect to Redis: %v. Please ensure Redis is running.", err)
	}
	log.Println("Successfully connected to Redis.")
}

func main() {
	log.Println("Starting comprehensive DNS server...")

	setupRedis()

	port := 53
	addr := ":" + strconv.Itoa(port)

	handler := NewDNSServerHandler(defaultUpstreamDNSServer)

	// Start UDP server
	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	log.Printf("Listening on UDP %s\n", addr)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %s\n", err.Error())
		}
	}()

	// Start TCP server 
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}
	log.Printf("Listening on TCP %s\n", addr)
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start TCP server: %s\n", err.Error())
	}
}
