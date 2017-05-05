package main

// Dns Message format: http://www.zytrax.com/books/dns/ch15/

import (
	"fmt"
	"flag"
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

//
// REST API messages
//

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

//
// Database interface
//

type Database struct {
	db	*scribble.Driver
}

func NewDatabase(scribbleDbDir string) (error, *Database) {
	db, err := scribble.New(scribbleDbDir, nil)
	if err != nil {
		return err, nil
	}
	database := Database{db: db}
	return nil, &database
}

func (d Database) Write(dnsRecord DnsMessage) error {
	log.Printf("Saving %s to db\n", dnsRecord)
	// We have 1 document in the db for every entry in Question section
	for _, question := range dnsRecord.Question {
		err := d.db.Write(strconv.Itoa(int(question.Qtype)), question.Qname, dnsRecord)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d Database) Read(dnsRecord DnsMessage) (error, DnsMessage) {
	log.Printf("Querying DNS Record %s\n", dnsRecord)
	// TODO Need to support > 1 question
	question := dnsRecord.Question[0]
	returnDnsRecord := DnsMessage{}
	err := d.db.Read(strconv.Itoa(int(question.Qtype)), question.Qname, &returnDnsRecord)
	if err == nil {
		returnDnsRecord.MsgHdr.Rcode = dns.RcodeSuccess
	} else {
		log.Printf("Could not find record. %s\n", err)
		returnDnsRecord.MsgHdr.Rcode = dns.RcodeNameError
	}
	log.Printf("Responding to DNS Record query with %s\n", returnDnsRecord)
	return err, returnDnsRecord
}

func (d Database) Delete(dnsRecord DnsMessage) error {
	log.Printf("Deleting DNS Record %s\n", dnsRecord)
	// TODO Need to support > 1 question
	question := dnsRecord.Question[0]
	err := d.db.Delete(strconv.Itoa(int(question.Qtype)), question.Qname)
	return err
}

//
// DNS functions
//

func operationQuery(database *Database, dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) *dns.Msg {
	// TODO Dont assume only 1 question. Query db once for every question
	queryDomain := requestDnsMsg.Question[0].Name
	qtype := requestDnsMsg.Question[0].Qtype
	log.Printf("Received query type %s for domain %s. Question is %s\n", qtype, queryDomain, requestDnsMsg.Question)

	// Query db for queryDomain
	// TODO Type 255 (dns.TypeANY) means any/all records
	dnsQuery := DnsQuestion{Qname: queryDomain, Qtype: qtype}
	queryDnsRecord := DnsMessage{Question: []DnsQuestion{dnsQuery}}
	log.Printf("Searchign database for record: %s\n", queryDnsRecord)
	err, answerDnsMessage := database.Read(queryDnsRecord)
	if err != nil {
		log.Printf("Error querying for record: %s. Error was: %s\n", queryDnsRecord, err)
		// TODO handle error (?).
		// answerDnsMessage should already be RcodeNameError, so no need to do anything?
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
func handleDnsQuery(database *Database) func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {
	return func (dnsResponseWriter dns.ResponseWriter, requestDnsMsg *dns.Msg) {

		switch requestDnsMsg.Opcode {
		case dns.OpcodeQuery:
			log.Printf("Query requested. Continuing.\n")
			dnsMsg := operationQuery(database, dnsResponseWriter, requestDnsMsg)
			// Finally send the DNS message
			dnsResponseWriter.WriteMsg(dnsMsg)
		default:
			log.Printf("Opcode %s not supported\n", requestDnsMsg.Opcode)
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
// net: (string) "tcp" or "udp"
// listenAddr: (string) ip addr and port to listen on
// name: (string) DNSSEC  name.
// secret: (string) DNSSEC TSIG.
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

// Runs REST API HTTP server forever.
//
// httpListenAddr: (string) interface and port to listen on
// database: (*Database) Reference to local database that stores DNS records.
func serveRestApi(httpListenAddr string, database *Database) {
	log.Printf("Starting REST API listener on %s\n", httpListenAddr)
	http.HandleFunc("/v1/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if r.Body == nil {
				http.Error(w, "Empty body not allowed", http.StatusBadRequest)
				return
			}
			var dnsRecord DnsMessage
			if err := json.NewDecoder(r.Body).Decode(&dnsRecord); err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// TODO validate dnsRecord
			log.Printf("Saving %s\n", dnsRecord)
			if err := database.Write(dnsRecord); err != nil {
				log.Printf("Error saving %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO return 204 No content
		} else if r.Method == http.MethodDelete {
			if r.Body == nil {
				http.Error(w, "Empty body not allowed", http.StatusBadRequest)
				return
			}
			var dnsRecord DnsMessage
			if err := json.NewDecoder(r.Body).Decode(&dnsRecord); err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// TODO validate dnsRecord
			if err := database.Delete(dnsRecord); err != nil {
				log.Printf("Error deleting %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
	// User-provided parameters
	var tsigName, tsigSecret string
	// Via environment variables
	dnsListenTcp, ok := os.LookupEnv("YESDNS_DNS_LISTEN_TCP")
	if ! ok { dnsListenTcp = "0.0.0.0:8053" }
	dnsListenUdp, ok := os.LookupEnv("YESDNS_DNS_LISTEN_UDP")
	if ! ok { dnsListenUdp = "0.0.0.0:8053" }
	httpListen, ok := os.LookupEnv("YESDNS_HTTP_LISTEN")
	if ! ok { httpListen = "0.0.0.0:8080" }
	dbDir, ok := os.LookupEnv("YESDNS_DB_DIR")
	if ! ok { dbDir = "./db/v1" }
	// Via command line
	dnsListenTcp = *flag.String("dns-listen-tcp", dnsListenTcp, "IP address and TCP port to serve DNS on. Also env var YESDNS_DNS_LISTEN_TCP")
	dnsListenUdp = *flag.String("dns-listen-udp", dnsListenUdp, "IP address and UDP port to serve DNS on. Also env var YESDNS_DNS_LISTEN_UDP")
	httpListen = *flag.String("http-listen", httpListen, "IP address and TCP port to serve HTTP on. Also env var YESDNS_HTTP_LISTEN")
	dbDir = *flag.String("db-dir", dbDir, "Directory to store Scribble database in. Also env var YESDNS_DB_DIR")
	flag.Parse()

	// Initialize database
	// TODO Possible traversal attack via dbDir?
	err, database := NewDatabase(dbDir)
	if err != nil {
		log.Printf("Could not open database %s\n", dbDir)
		return
	}

	// Register DNS query handler
	dns.HandleFunc(".", handleDnsQuery(database) )

	// Start up DNS listeners
	go serveDns("tcp", dnsListenTcp, tsigName, tsigSecret)
	go serveDns("udp", dnsListenUdp, tsigName, tsigSecret)

	// Start up REST API
	go serveRestApi(httpListen, database)

	// Wait for process to be stopped by user
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Waiting forever for SIGINT OR SIGTERM")
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
