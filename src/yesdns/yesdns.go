package main

// Dns Message format: http://www.zytrax.com/books/dns/ch15/

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
	"os"
	"os/signal"
	"syscall"
	"net/http"
	"log"
	"encoding/json"
	"github.com/nanobox-io/golang-scribble"
	"net"
	"strconv"
)

type DnsHeader struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Rcode              int
}

type DnsRR struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
	Ttl   uint32 `json:"ttl"`
	Rdata interface{} `json:"rdata"`
}

type DnsQuestion struct {
	Qname  string	`json:"qname"`
	Qtype  uint16	`json:"qtype"`
	Qclass uint16	`json:"qclass"`
}

type DnsMessage struct {
	MsgHdr   DnsHeader
	Question []DnsQuestion
	Answer   []DnsRR
	Ns       []DnsRR
	Extra    []DnsRR
}

func handleDbDnsQuery(queryChannel chan DnsMessage) func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {
	return func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {

		// Initialize response message and set header flags
		dnsMsg := new(dns.Msg)
		// TODO m.Compress = *compress

		// TODO Dont assume only 1 question. Query db once for every question
		queryDomain := requestDnsMsg.Question[0].Name
		qtype := requestDnsMsg.Question[0].Qtype
		log.Printf("Received query type %s for domain %s\n", qtype, queryDomain)
		log.Printf("Question is %s\n", requestDnsMsg.Question)

		// Query db for queryDomain
		// TODO Type 255 (dns.TypeANY) means any/all records
		dnsQuery := DnsQuestion{Qname: queryDomain, Qtype: qtype}
		queryDnsRecord := DnsMessage{Question: []DnsQuestion{dnsQuery}}
		log.Printf("Querying for record: %s\n", queryDnsRecord)
		queryChannel <- queryDnsRecord

		// Wait for query to be answered
		log.Printf("Waiting for response to query: %s\n", queryDnsRecord)
		answerDnsMessage := <- queryChannel

		// Build up response message Header
		dnsMsg.Rcode = answerDnsMessage.MsgHdr.Rcode
		dnsMsg.Id = requestDnsMsg.Id
		dnsMsg.RecursionDesired = requestDnsMsg.RecursionDesired // Copy rd bit
		dnsMsg.Response = true
		dnsMsg.Opcode = dns.OpcodeQuery
		// We default to Success, but this can change
		dnsMsg.Rcode = dns.RcodeSuccess
		// TODO support recursion (one day)
		dnsMsg.RecursionAvailable = false
		// Build response Question section
		for _, questionSection := range answerDnsMessage.Question {
			dnsQuestion := dns.Question{Name: questionSection.Qname, Qtype: questionSection.Qtype, Qclass: questionSection.Qclass}
			dnsMsg.Question = append(dnsMsg.Question, dnsQuestion)
		}
		// Build response Answer section
		for _, rrSection := range answerDnsMessage.Answer {
			switch rrSection.Type {
			// TODO Support SOA records
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
			}
		}

		if requestDnsMsg.IsTsig() != nil {
			if dnsResponseWriter.TsigStatus() == nil {
				dnsMsg.SetTsig(requestDnsMsg.Extra[len(requestDnsMsg.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
			} else {
				log.Println("Status", dnsResponseWriter.TsigStatus().Error())
			}
		}

		// Finally send the DNS message
		dnsResponseWriter.WriteMsg(dnsMsg)
	}
}

func serveDns(net, listenAddr, name, secret string) {
	log.Printf("Starting listener on %s %s\n", net, listenAddr)
	switch name {
	case "":
		server := &dns.Server{Addr: listenAddr, Net: net, TsigSecret: nil}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: listenAddr, Net: net, TsigSecret: map[string]string{name: secret}}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func serveDb(scribbleDbDir string, saveChannel chan DnsMessage, queryChannel chan DnsMessage, deleteChannel chan DnsMessage) {
	// Start up scribble db
	db, err := scribble.New(scribbleDbDir, nil)
	if err != nil {
		log.Println("Error", err)
		return
	}
	for { // Loop forever over select statement
		select {
		case dnsRecord := <- saveChannel:
			log.Printf("Saving %s to db\n", dnsRecord)
			// We have 1 document in the db for every entry in Question section
			for _, question := range dnsRecord.Question {
				err := db.Write(strconv.Itoa(int(question.Qtype)), question.Qname, dnsRecord)
				if err != nil {
					fmt.Printf("%s\n", err)
				}
			}
			// TODO respond with something
		case dnsRecord := <- queryChannel:
			log.Printf("Querying DNS Record %s\n", dnsRecord)
			// TODO Need to support > 1 question
			question := dnsRecord.Question[0]
			returnDnsRecord := DnsMessage{}
			if err := db.Read(strconv.Itoa(int(question.Qtype)), question.Qname, &returnDnsRecord); err == nil {
				returnDnsRecord.MsgHdr.Rcode = dns.RcodeSuccess
			} else {
				log.Printf("Could not find record. %s\n", err)
				returnDnsRecord.MsgHdr.Rcode = dns.RcodeNameError
			}
			log.Printf("Responding to DNS Record query with %s\n", returnDnsRecord)
			queryChannel <- returnDnsRecord
		case dnsRecord := <- deleteChannel:
			log.Printf("Deleting DNS Record %s\n", dnsRecord)
			question := dnsRecord.Question[0]
			db.Delete(strconv.Itoa(int(question.Qtype)), question.Qname)
			deleteChannel <- dnsRecord
		}
	}
}

func serveRestApi(httpListenAddr string, saveChannel chan DnsMessage, deleteChannel chan DnsMessage) {
	log.Printf("Starting REST API listener on %s\n", httpListenAddr)
	http.HandleFunc("/v1/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if r.Body == nil {
				http.Error(w, "Empty body not allowed", http.StatusBadRequest)
			}
			var dnsRecord DnsMessage
			if err := json.NewDecoder(r.Body).Decode(&dnsRecord); err != nil {
				log.Println(err)
				http.Error(w, err.Error(), 400)
				return
			}
			// TODO validate dnsRecord
			log.Printf("Saving %s\n", dnsRecord)
			saveChannel <- dnsRecord
			// TODO read something and check status
		} else if r.Method == http.MethodDelete {
			if r.Body == nil {
				http.Error(w, "Empty body not allowed", http.StatusBadRequest)
			}
			var dnsRecord DnsMessage
			if err := json.NewDecoder(r.Body).Decode(&dnsRecord); err != nil {
				log.Println(err)
				http.Error(w, err.Error(), 400)
				return
			}
			// TODO validate dnsRecord
			deleteChannel <- dnsRecord
			// TODO check response: deleteResponse := <- deleteChannel
			// TODO Return 204 No Content
		} else {
			msg := fmt.Sprintf("Method %s not allowed for /v1/record\n", r.Method)
			// TODO return json error message
			http.Error(w, msg, http.StatusMethodNotAllowed)
		}
	})
	// Start serving REST API forever
	log.Fatal(http.ListenAndServe(httpListenAddr, nil))
}

func main() {
	// User parameters
	var name, secret string
	dnsListenAddr := ":8053"
	httpListenAddr := ":8080"
	scribbleDbDir := "./db/v1"

	queryChannel := make(chan DnsMessage)
	saveChannel := make(chan DnsMessage)
	deleteChannel := make(chan DnsMessage)

	// Register DNS query handler
	dns.HandleFunc(".", handleDbDnsQuery(queryChannel) )

	// Start up the database
	go serveDb(scribbleDbDir, saveChannel, queryChannel, deleteChannel)

	// Start up DNS listeners
	go serveDns("tcp", dnsListenAddr, name, secret)
	go serveDns("udp", dnsListenAddr, name, secret)

	// Start up REST API
	go serveRestApi(httpListenAddr, saveChannel, deleteChannel)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Waiting forever for SIGINT OR SIGTERM")
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
