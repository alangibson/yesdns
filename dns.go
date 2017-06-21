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

// Handles DNS Query operation (OpCode 0)
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
func queryOperation(database *Database, dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg, resolver *Resolver) *dns.Msg {
	queryDomain := requestDnsMsg.Question[0].Name
	qtype := requestDnsMsg.Question[0].Qtype

	// Try to resolve query and set status
	err, resolvedDnsMessage := resolver.Resolve(qtype, queryDomain)
	if err != nil {
		// Lookup failed
		return &dns.Msg{
			Compress: false,
			MsgHdr: dns.MsgHdr{
				Id: requestDnsMsg.Id,
				Opcode: requestDnsMsg.Opcode,
				RecursionDesired: requestDnsMsg.RecursionDesired,
				Rcode: dns.RcodeServerFailure,
				RecursionAvailable: false,
				Response: true,
				Authoritative: false,
			},
		}
	} else if resolvedDnsMessage == nil {
		// Lookup did not error, but nothing found
		return &dns.Msg{
			Compress: false,
			MsgHdr: dns.MsgHdr{
				Id: requestDnsMsg.Id,
				Opcode: requestDnsMsg.Opcode,
				RecursionDesired: requestDnsMsg.RecursionDesired,
				Rcode: dns.RcodeNameError, // aka NXDomain
				RecursionAvailable: false,
				Response: true,
				Authoritative: false,
			},
		}
	} // else: lookup did not error and answer found

	returnDnsMsg := &dns.Msg{
		Compress: false,
		MsgHdr: dns.MsgHdr{
			Id: requestDnsMsg.Id,
			RecursionDesired: requestDnsMsg.RecursionDesired,
			Opcode: requestDnsMsg.Opcode,
			Response: true, 												// QR, Query/Response. 1 bit. 0=Query, 1=Response
			// go's 'zero value' for int is 0, which == rcode 0 (NoError)
			Rcode: resolvedDnsMessage.MsgHdr.Rcode,
			// go's 'zero value' for boolean is false, so these all default to false if not supplied in json
			RecursionAvailable: resolvedDnsMessage.MsgHdr.RecursionAvailable,
			Authoritative: resolvedDnsMessage.MsgHdr.Authoritative,			// AA, Authoritative Answer. 1 bit. 0=Not authoritative, 1=Is authoritative
			Truncated: resolvedDnsMessage.MsgHdr.Truncated, 				// TC, Truncated. 1 bit. 0=Not truncated, 1=Message truncated
			Zero: resolvedDnsMessage.MsgHdr.Zero,
			AuthenticatedData: resolvedDnsMessage.MsgHdr.AuthenticatedData, // AD, Authenticated data. 1 bit. All data in the response has been cryptographically verified or otherwise meets the server's local security policy.
			CheckingDisabled: resolvedDnsMessage.MsgHdr.CheckingDisabled, 	// CD, Checking Disabled. 1 bit.
		},
	}
	
	// Build response Question section
	for _, questionSection := range resolvedDnsMessage.Question {
		dnsQuestion := dns.Question{Name: questionSection.Qname, Qtype: questionSection.Qtype, Qclass: questionSection.Qclass}
		returnDnsMsg.Question = append(returnDnsMsg.Question, dnsQuestion)
	}
	// Build response Answer section
	for _, rrSection := range resolvedDnsMessage.Answer {
		switch rrSection.Type {
		case dns.TypeA:
			dnsRR := &dns.A{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				A: net.ParseIP(rrSection.Rdata.(string)),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
		case dns.TypeAAAA:
			dnsRR := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				AAAA: net.ParseIP(rrSection.Rdata.(string)),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
		case dns.TypeCNAME:
			dnsRR := &dns.CNAME{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Target: rrSection.Rdata.(string),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
		case dns.TypeNS:
			dnsRR := &dns.NS{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ns: rrSection.Rdata.(string),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
		case dns.TypePTR:
			dnsRR := &dns.PTR{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ptr: rrSection.Rdata.(string),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
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
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
		case dns.TypeSRV:
			rdataMap := rrSection.Rdata.(map[string]interface{})
			dnsRR := &dns.SRV{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Priority: uint16(rdataMap["priority"].(float64)),
				Weight: uint16(rdataMap["weight"].(float64)),
				Port: uint16(rdataMap["port"].(float64)),
				Target: rdataMap["target"].(string),
			}
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsRR)
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
			returnDnsMsg.Answer = append(returnDnsMsg.Answer, dnsTXT)
			// TODO? dnsMsg.Extra = append(dnsMsg.Extra, dnsRR)
		default:
			log.Printf("WARN Cant build Answer section for type: %s.\n", rrSection.Type)
			// TODO return error to client?
		}
	}
	// Build response Authority section
	for _, rrSection := range resolvedDnsMessage.Ns {
		switch rrSection.Type {
		case dns.TypeNS:
			dnsRR := &dns.NS{
				Hdr: dns.RR_Header{Name: rrSection.Name, Rrtype: rrSection.Type, Class: rrSection.Class, Ttl: rrSection.Ttl},
				Ns: rrSection.Rdata.(string),
			}
			returnDnsMsg.Ns = append(returnDnsMsg.Ns, dnsRR)
		default:
			log.Printf("WARN Cant build Authority section for type: %s.\n", rrSection.Type)
		}
	}
	// Build response Extra section
	for _, rrSection := range resolvedDnsMessage.Extra {
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
			returnDnsMsg.Extra = append(returnDnsMsg.Extra, dnsRR)
		default:
			log.Printf("WARN Cant build Extra section for type: %s.\n", rrSection.Type)
		}
	}

	if requestDnsMsg.IsTsig() != nil {
		if dnsResponseWriter.TsigStatus() == nil {
			returnDnsMsg.SetTsig(requestDnsMsg.Extra[len(requestDnsMsg.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			log.Println("DEBUG Status", dnsResponseWriter.TsigStatus().Error())
		}
	}
	return returnDnsMsg
}

// DNS query handler. Dispatches to operation handlers based on query OpCode.
// We use a closure to maintain a reference to the database.
func handleDnsQuery(database *Database, resolver *Resolver) func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {
	return func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {

		log.Printf("DEBUG Received query with local addr %s network %s. Message is: \n%s\n",
			dnsResponseWriter.LocalAddr(), dnsResponseWriter.LocalAddr().Network(), requestDnsMsg)
		
		switch requestDnsMsg.Opcode {
		case dns.OpcodeQuery:
			// Try to find answer in our internal db
			log.Printf("DEBUG Trying internal resolution\n")
			dnsMsg := queryOperation(database, dnsResponseWriter, requestDnsMsg, resolver)
			log.Printf("DEBUG Internal resolution Rcode is %s\n", dnsMsg.Rcode)
			if dnsMsg.Rcode == dns.RcodeSuccess {
				log.Printf("DEBUG Internal resolution succeeded. Responding with message \n%s\n", dnsMsg)
				dnsResponseWriter.WriteMsg(dnsMsg)
				return
			}
			// We did not succeed in internal lookup, so try forwarders
			log.Printf("DEBUG Trying forwarders\n")
			err, forwardDnsMsg := resolver.Forward(requestDnsMsg)
			if err == nil && forwardDnsMsg != nil {
				// Return successful forward resolution
				log.Printf("DEBUG Forward resolution succeeded with Rcode %s. Responding with message: \n%s\n", forwardDnsMsg.Rcode, forwardDnsMsg)
				dnsResponseWriter.WriteMsg(forwardDnsMsg)
			} else {
				// TODO separate log message for nil and not nil forwardDnsMsg
				// TODO is this correct behavior?
				// Default to our (failed) internal lookup
				log.Printf("DEBUG Forward resolution failed. Returning (failed) internal lookup: \n%s\n", dnsMsg)
				dnsResponseWriter.WriteMsg(dnsMsg)
			}
		default:
			log.Printf("WARN Opcode %s not supported\n", requestDnsMsg.Opcode)
			// Return a failure message
			dnsMsg := new(dns.Msg)
			dnsMsg.Rcode = dns.RcodeNotImplemented
			dnsMsg.Id = requestDnsMsg.Id
			dnsMsg.RecursionDesired = requestDnsMsg.RecursionDesired // Copy rd bit
			dnsMsg.Response = true
			dnsMsg.Opcode = requestDnsMsg.Opcode
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
	log.Printf("DEBUG Starting DNS listener on %s %s\n", net, listenAddr)

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
			log.Printf("DEBUG Closed " + net + " server: %s\n", err.Error())
		}
	}()

	// Wait (possibly forever) for shutdown signal
	select {
	case <-shutdownChannel:
		server.Shutdown()
	}
}
