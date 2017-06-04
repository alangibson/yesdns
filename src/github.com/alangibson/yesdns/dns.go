package yesdns

// Dns Message format: http://www.zytrax.com/books/dns/ch15/

// Depends on:
// db.go/Database
import (
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
)

//
// DNS functions
//

func operationQuery(database *Database, dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg, resolverId string) *dns.Msg {
	// TODO Dont assume only 1 question. Query db once for every question
	queryDomain := requestDnsMsg.Question[0].Name
	qtype := requestDnsMsg.Question[0].Qtype
	log.Printf("Received query type %s for domain %s. Question is %s\n", qtype, queryDomain, requestDnsMsg.Question)

	// Query db for queryDomain
	// TODO Type 255 (dns.TypeANY) means any/all records
	//dnsQuery := DnsQuestion{Qname: queryDomain, Qtype: qtype}
	//queryDnsRecord := DnsMessage{Question: []DnsQuestion{dnsQuery}}
	//log.Printf("Searching database for record: %s\n", queryDnsRecord)
	// err, answerDnsMessage := database.ReadDnsMessage(queryDnsRecord)

	// TODO hide this db call in a function in the Resolver class
	err, answerDnsMessage := database.ReadResolverDnsMessage(resolverId, qtype, queryDomain)
	if err != nil {
		log.Printf("Could not find record. %s\n", err)

		// TODO If err indicates record not found and forwarder configured, forward request
		// err, forwarders := database.ReadAllForwarders()
		//for _, forwarder := range forwarders {
			// TODO send new dns request to forwarder.Address
		//}

		// TODO only set this if forwarding fails
		answerDnsMessage.MsgHdr.Rcode = dns.RcodeNameError

	} else {
		log.Printf("Responding to DNS Record query with %s\n", answerDnsMessage)
		answerDnsMessage.MsgHdr.Rcode = dns.RcodeSuccess
	}
	
	// Initialize response message and set header flags
	// TODO dont use new, use composite literal instead
	dnsMsg := new(dns.Msg)
	// TODO m.Compress = *compress
	// Build up response message Header
	dnsMsg.Rcode = answerDnsMessage.MsgHdr.Rcode
	dnsMsg.Id = requestDnsMsg.Id
	dnsMsg.RecursionDesired = requestDnsMsg.RecursionDesired // Copy rd bit
	dnsMsg.Response = true
	dnsMsg.Opcode = dns.OpcodeQuery
	// We default to Success, but this can change
	dnsMsg.Rcode = dns.RcodeSuccess
	// FIXME RecursionAvailable = true when we have forwarders configured
	dnsMsg.RecursionAvailable = false
	// Build response Question section
	for _, questionSection := range answerDnsMessage.Question {
		dnsQuestion := dns.Question{Name: questionSection.Qname, Qtype: questionSection.Qtype, Qclass: questionSection.Qclass}
		dnsMsg.Question = append(dnsMsg.Question, dnsQuestion)
	}
	// Build response Answer section
	for _, rrSection := range answerDnsMessage.Answer {
		switch rrSection.Type {
		case dns.TypeA:
			dnsRR := &dns.A{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				A: net.ParseIP(rrSection.Rdata.(string)),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeAAAA:
			dnsRR := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				AAAA: net.ParseIP(rrSection.Rdata.(string)),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeCNAME:
			dnsRR := &dns.CNAME{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Target: rrSection.Rdata.(string),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeNS:
			dnsRR := &dns.NS{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ns: rrSection.Rdata.(string),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypePTR:
			dnsRR := &dns.PTR{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ptr: rrSection.Rdata.(string),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeSOA:
			rdataMap := rrSection.Rdata.(map[string]interface{})
			dnsRR := &dns.SOA{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ns: rdataMap["ns"].(string),
				Mbox: rdataMap["mbox"].(string),
				Serial: uint32(rdataMap["serial"].(float64)),
				Refresh: uint32(rdataMap["refresh"].(float64)),
				Retry: uint32(rdataMap["retry"].(float64)),
				Expire: uint32(rdataMap["expire"].(float64)),
				Minttl: uint32(rdataMap["minttl"].(float64)),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeSRV:
			rdataMap := rrSection.Rdata.(map[string]interface{})
			dnsRR := &dns.SRV{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Priority: uint16(rdataMap["priority"].(float64)),
				Weight: uint16(rdataMap["weight"].(float64)),
				Port: uint16(rdataMap["port"].(float64)),
				Target: rdataMap["target"].(string),
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsRR)
		case dns.TypeTXT:
			// Convert rdata to slice of string
			txtLines := make([]string, len(rrSection.Rdata.([]interface{})))
			for _, line := range rrSection.Rdata.([]interface{}) {
				txtLines = append(txtLines, line.(string))
			}
			dnsTXT := &dns.TXT{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Txt: txtLines,
			}
			dnsMsg.Answer = append(dnsMsg.Answer, dnsTXT)
			// TODO? dnsMsg.Extra = append(dnsMsg.Extra, dnsRR)
		default:
			log.Printf("Cant build Answer section for type: %s.\n", rrSection.Type)
			// TODO return error to client?
		}
	}
	// Build response Authority section
	for _, rrSection := range answerDnsMessage.Ns {
		switch rrSection.Type {
		case dns.TypeNS:
			dnsRR := &dns.NS{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ns: rrSection.Rdata.(string),
			}
			dnsMsg.Ns = append(dnsMsg.Ns, dnsRR)
		default:
			log.Printf("Cant build Authority section for type: %s.\n", rrSection.Type)
		}
	}
	// Build response Extra section
	for _, rrSection := range answerDnsMessage.Extra {
		switch rrSection.Type {
		case dns.TypeTXT:
			// Convert rdata to slice of string
			txtLines := make([]string, len(rrSection.Rdata.([]interface{})))
			for _, line := range rrSection.Rdata.([]interface{}) {
				txtLines = append(txtLines, line.(string))
			}
			dnsRR := &dns.TXT{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Txt: txtLines,
			}
			dnsMsg.Extra = append(dnsMsg.Extra, dnsRR)
		default:
			log.Printf("Cant build Extra section for type: %s.\n", rrSection.Type)
		}
	}

	if requestDnsMsg.IsTsig() != nil {
		if dnsResponseWriter.TsigStatus() == nil {
			dnsMsg.SetTsig(requestDnsMsg.Extra[len(requestDnsMsg.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			log.Println("Status", dnsResponseWriter.TsigStatus().Error())
		}
	}
	return dnsMsg
}

//
// Server Functions
//

// DNS query handler.
// We use a closure to maintain a reference to the database.
func handleDnsQuery(database *Database, resolverId string) func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {
	return func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {

		log.Printf("Handling query with local addr (%s) network: %s\n",
			dnsResponseWriter.LocalAddr(),
			dnsResponseWriter.LocalAddr().Network())

		switch requestDnsMsg.Opcode {
		case dns.OpcodeQuery:
			log.Printf("Query requested. Continuing.\n")
			dnsMsg := operationQuery(database, dnsResponseWriter, requestDnsMsg, resolverId)
			// Finally send the DNS message
			dnsResponseWriter.WriteMsg(dnsMsg)
		default:
			log.Printf("Opcode %s not supported\n", requestDnsMsg.Opcode)
			// Return a failure message
			// TODO dont use new(), use composite literal instead
			dnsMsg := new(dns.Msg)
			dnsMsg.Rcode = dns.RcodeNotImplemented
			dnsMsg.Id = requestDnsMsg.Id
			dnsMsg.RecursionDesired = requestDnsMsg.RecursionDesired // Copy rd bit
			dnsMsg.Response = true
			dnsMsg.Opcode = requestDnsMsg.Opcode
			// FIXME set RecursionAvailable = true when forwarders configured
			dnsMsg.RecursionAvailable = false
			dnsResponseWriter.WriteMsg(dnsMsg)
		}
	}
}

// Runs DNS server forever.
//
// if we read something from shutdownChannel, call server.Shutdown()
//
// net: (string) "tcp" or "udp"
// listenAddr: (string) ip addr and port to listen on
// name: (string) DNSSEC  name.
// secret: (string) DNSSEC TSIG.
func serveDns(net, listenAddr, name, secret string, handler dns.Handler, shutdownChannel chan int) {
	log.Printf("Starting listener on %s %s\n", net, listenAddr)

	var server *dns.Server

	// Support for TSIG
	switch name {
	case "":
		server = &dns.Server{Addr: listenAddr, Net: net, TsigSecret: nil, Handler: handler}
	default:
		server = &dns.Server{Addr: listenAddr, Net: net, TsigSecret: map[string]string{name: secret}, Handler: handler}
	}

	// Start this up in an anonymous goroutine because server.ListenAndServe() blocks
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Closed " + net + " server: %s\n", err.Error())
		}
	}()

	// Wait (possibly forever) for shutdown signal
	select {
	case <-shutdownChannel:
		server.Shutdown()
	}
}
