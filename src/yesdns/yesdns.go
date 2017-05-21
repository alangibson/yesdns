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
	"bytes"
)

type DNSServerState struct {
	ServeMux 		*dns.ServeMux
	Patterns		[]string
	ShutdownChannel	chan int
	Listener		ResolverListener
}
var RunningDNSServers map[string]DNSServerState

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
	Resolvers  []string		`json:"resolvers"`
	MsgHdr     DnsHeader
	Question   []DnsQuestion
	Answer     []DnsRR
	Ns         []DnsRR
	Extra      []DnsRR
}

type Forwarder struct {
	Address string	`json:"address"`
}

type ResolverStore struct {
	Type 	string 	`json:"type"`
}

type ResolverListener struct {
	Net 	string	`json:"net"`
	Address	string	`json:"address"`
}

func (rl ResolverListener) Key() string {
	return rl.Address + "-" + rl.Net
}

type Resolver struct {
	Id 		string			`json:"id"`
	Patterns 	[]string		`json:"patterns"`
	Store 		ResolverStore		`json:"store"`
	Listeners 	[]ResolverListener	`json:"listeners"`
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

func (d Database) WriteDnsMessage(dnsRecord DnsMessage) error {
	log.Printf("Saving %s to db\n", dnsRecord)

	// We create records for every resolver
	for _, resolverId := range dnsRecord.Resolvers {
		// We have 1 document in the db for every entry in Question section
		for _, question := range dnsRecord.Question {
			key := resolverId + "/" + strconv.Itoa(int(question.Qtype))
			err := d.db.Write(key, question.Qname, dnsRecord)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (d Database) WriteForwarder(forwarder Forwarder) error {
	return d.db.Write("forwarders", forwarder.Address, forwarder)
}

func (d Database) WriteResolver(resolver Resolver) error {
	err := d.db.Write("resolvers", resolver.Id, resolver)
	return err
}

func (d Database) ReadDnsMessage(dnsRecord DnsMessage) (error, DnsMessage) {
	log.Printf("Querying DNS Record %s\n", dnsRecord)
	// TODO Need to support > 1 question
	question := dnsRecord.Question[0]
	returnDnsRecord := DnsMessage{}
	// TODO look up by resolver.id/question.qtype
	err := d.db.Read(strconv.Itoa(int(question.Qtype)), question.Qname, &returnDnsRecord)
	return err, returnDnsRecord
}

func (d Database) ReadResolverDnsMessage(resolverId string, qtype uint16, qname string) (error, DnsMessage) {
	returnDnsRecord := DnsMessage{}
	key := resolverId + "/" + strconv.Itoa(int(qtype))
	err := d.db.Read(key, qname, &returnDnsRecord)
	return err, returnDnsRecord
}

func (d Database) ReadAllForwarders() (error, []Forwarder) {
	jsonStrings, err := d.db.ReadAll("forwarders")
	// Return nil if there are no Forwarders
	if len(jsonStrings) == 0 {
		return err, nil
	}
	// Convert jsonString []string to []Forwarder
	var forwarders []Forwarder
	for _, jsonString := range jsonStrings {
		var forwarder Forwarder
		if err := json.NewDecoder(bytes.NewBufferString(jsonString)).Decode(&forwarder); err != nil {
			log.Printf("Could not decode json: %s\n", err)
		} else {
			forwarders = append(forwarders, forwarder)
		}
	}
	return err, forwarders
}

func (d Database) ReadAllResolvers() (error, []Resolver) {
	jsonStrings, err := d.db.ReadAll("resolvers")
	// Return nil if there are no Forwarders
	if len(jsonStrings) == 0 {
		return err, nil
	}
	// TODO Convert jsonString []string to []Resolver
	var resolvers []Resolver
	for _, jsonString := range jsonStrings {
		var resolver Resolver
		if err := json.NewDecoder(bytes.NewBufferString(jsonString)).Decode(&resolver); err != nil {
			log.Printf("Could not decode json: %s\n", err)
		} else {
			resolvers = append(resolvers, resolver)
		}
	}
	return err, resolvers
}

func (d Database) DeleteDnsMessage(dnsRecord DnsMessage) error {
	log.Printf("Deleting DNS Record %s\n", dnsRecord)
	// TODO Need to support > 1 question
	question := dnsRecord.Question[0]
	err := d.db.Delete(strconv.Itoa(int(question.Qtype)), question.Qname)
	return err
}

func (d Database) DeleteForwarder(forwarder Forwarder) error {
	return d.db.Delete("forwarders", forwarder.Address)
}

func (d Database) DeleteResolver(resolver Resolver) error {
	log.Printf("Deleting resolver %s\n", resolver.Id)
	err := d.db.Delete("resolvers", resolver.Id)
	return err
}

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

// Runs REST API HTTP server forever.
//
// httpListenAddr: (string) interface and port to listen on
// database: (*Database) Reference to local database that stores DNS records.
func serveRestApi(httpListenAddr string, database *Database) {
	log.Printf("Starting REST API listener on %s\n", httpListenAddr)

	http.HandleFunc("/v1/message", func(w http.ResponseWriter, r *http.Request) {
		// Decode json
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
		// Handle method
		if r.Method == http.MethodPut {
			// TODO validate dnsRecord
			log.Printf("Saving %s\n", dnsRecord)
			if err := database.WriteDnsMessage(dnsRecord); err != nil {
				log.Printf("Error saving %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO return 204 No content
		} else if r.Method == http.MethodDelete {
			// TODO validate dnsRecord
			if err := database.DeleteDnsMessage(dnsRecord); err != nil {
				log.Printf("Error deleting %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO Return 204 No Content
		} else {
			msg := fmt.Sprintf("Method %s not allowed for /v1/message\n", r.Method)
			// TODO return json error message
			http.Error(w, msg, http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/v1/forwarder", func(w http.ResponseWriter, r *http.Request) {
		// Decode json
		if r.Body == nil {
			http.Error(w, "Empty body not allowed", http.StatusBadRequest)
			return
		}
		var forwarder Forwarder
		if err := json.NewDecoder(r.Body).Decode(&forwarder); err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		//log.Printf("Marshalled forwarder: %s\n", forwarder)
		// Handle method
		if r.Method == http.MethodPut {
			if err := database.WriteForwarder(forwarder); err != nil {
				log.Printf("Error writing %s. Error was: %s\n", forwarder, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if r.Method == http.MethodDelete {
			if err := database.DeleteForwarder(forwarder); err != nil {
				log.Printf("Error deleting %s. Error was: %s\n", forwarder, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			msg := fmt.Sprintf("Method %s not allowed for /v1/forwarder\n", r.Method)
			// TODO return json error message
			http.Error(w, msg, http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/v1/resolver", func(w http.ResponseWriter, r *http.Request) {
		// Decode json
		if r.Body == nil {
			http.Error(w, "Empty body not allowed", http.StatusBadRequest)
			return
		}
		var resolver Resolver
		if err := json.NewDecoder(r.Body).Decode(&resolver); err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("Marshalled resolver: %s\n", resolver)
		if r.Method == http.MethodPut {
			if err := database.WriteResolver(resolver); err != nil {
				log.Printf("Error writing %s. Error was: %s\n", resolver, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			syncResolversWithDatabase(database, RunningDNSServers)
		} else if r.Method == http.MethodDelete {
			if err := database.DeleteResolver(resolver); err != nil {
				log.Printf("Error deleting %s. Error was: %s\n", resolver, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			syncResolversWithDatabase(database, RunningDNSServers)
		} else {
			msg := fmt.Sprintf("Method %s not allowed for /v1/forwarder\n", r.Method)
			// TODO return json error message
			http.Error(w, msg, http.StatusMethodNotAllowed)
		}
	})

	// Start serving REST API forever
	log.Fatal(http.ListenAndServe(httpListenAddr, nil))
}

// Starts and stops resolvers based on config in database.
// Maps are a 'reference type', so even though we appear to pass by value, we really just get a reference.
func syncResolversWithDatabase(db *Database, runningDNSServers map[string]DNSServerState) {

	log.Printf("Reloading DNS servers from database\n")

	var keptKeys []string

	// TODO check error
	_, configuredResolvers := db.ReadAllResolvers()

	// Iterate over all resolvers configured in the database
	for _, configuredResolver := range configuredResolvers {

		// Iterate over configured listeners in each resolver and possibly start new ones
		for _, listener := range configuredResolver.Listeners {

			listenerKey := listener.Key()
			runningDNSServer, ok := runningDNSServers[listenerKey]

			if ok { // Server/Listener is already running

				// Make sure there is a handler attached to each server/listener for each pattern.
				for _, configuredPattern := range configuredResolver.Patterns {

					// See if pattern has already been added to running server/listener.
					inRunningListener := false
					for _, runningServerPattern := range runningDNSServer.Patterns {
						if configuredPattern == runningServerPattern {
							log.Printf("Found matching configured and running pattern (%s) in listener %s\n",
								configuredPattern, listenerKey)
							inRunningListener = true
							break
						}
					}

					// Do nothing if pattern already registered with handler.
					// Otherwise, create new handler and register pattern with running server.
					if inRunningListener {
						log.Printf("Pattern %s already registered on listener %s\n",
							configuredResolver.Patterns, listenerKey)

						// Record that this listener+pattern combo was in the configuration
						// TODO refactor: this is copied from Resolver.Keys()
						keptKeys = append(keptKeys, listener.Key() + "-" + configuredPattern)
					} else {
						// There is already a running dns.Server for this listener
						// Update handlers to serve configuredResolver.Pattern
						log.Printf("Adding pattern (%s) to running server %s\n",
							configuredResolver.Patterns, runningDNSServer)

						for _, configuredPattern := range configuredResolver.Patterns {
							
							// configuredResolver.Id
							runningDNSServer.ServeMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver.Id))
							// Add this pattern to the list of patterns this server will handle
							runningDNSServer.Patterns = append(runningDNSServer.Patterns, configuredPattern)
							log.Printf("After addition, patterns are: %s\n", runningDNSServer.Patterns)
							runningDNSServers[listenerKey] = runningDNSServer

							// Record that this listener+pattern combo was in the configuration
							// TODO refactor: this is copied from Resolver.Keys()
							keptKeys = append(keptKeys, listener.Key() + "-" + configuredPattern)
						}
					}
				}
			} else { // Server/Listener is not already running

				log.Printf("Starting new server on %s %s with pattern '%s'\n",
					listener.Net, listener.Address, configuredResolver.Patterns)
				// Create new dns.Server
				// Each listener (protocol+interface+port combo) has its own ServeMux, and hence its
				// own patter. name space.
				var serveMux = dns.NewServeMux()
				var patterns []string
				for _, configuredPattern := range configuredResolver.Patterns {

					// Register a handler for pattern
					serveMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver.Id))
					patterns = append(patterns, configuredPattern)

					// Record that this listener+pattern combo was in the configuration
					// TODO refactor: this is copied from Resolver.Keys()
					keptKeys = append(keptKeys, listener.Key() + "-" + configuredPattern)
				}

				// Start up DNS listeners
				// TODO support in rest api: go serveDns(listener.Net, listener.Address, tsigName, tsigSecret)
				shutdownChannel := make(chan int)
				go serveDns(listener.Net, listener.Address, "", "", serveMux, shutdownChannel)
				// Save shutdown channel for later use
				// TODO does this actually do anything?
				runningDNSServer.ShutdownChannel = shutdownChannel

				// Record new server/listener
				runningDNSServers[listenerKey] = DNSServerState{ShutdownChannel:shutdownChannel,
										ServeMux:serveMux, Patterns:patterns, Listener: listener}
				log.Printf("Added running server %s with listener key %s and patterns %s\n",
					runningDNSServers[listenerKey], listenerKey, patterns)
			}
		}
	}

	log.Printf("Keeping keys: %s\n", keptKeys)

	// Stop all running DNS servers, or just remove patterns from them, that were not in configuration this time
	for listenerKey, runningDNSServer := range runningDNSServers {

		log.Printf("Before removals, patterns are: %s\n", runningDNSServer.Patterns)
		
		// If listenerKey not in keptKeys, remove pattern from listener
		// for patternIndex, pattern := range runningDNSState.Patterns {
		j := 0
		for i := 0; i < len(runningDNSServer.Patterns); i++ {
			pattern := runningDNSServer.Patterns[i]
			// TODO refactor: key creation copied from somewhere else above
			runningKey := listenerKey + "-" + pattern
			inKeptKeys := false
			for _, keptKey := range keptKeys {
				log.Printf("Comparing kept key '%s' == running key '%s'\n", keptKey, runningKey)
				if keptKey == runningKey {
					log.Printf("Keeping %s\n", keptKey)
					inKeptKeys = true
				}
			}
			// Listener+pattern combo not in keptKeys, so remove it
			if ! inKeptKeys {
				log.Printf("Removing pattern %s from running server %s\n", pattern, listenerKey)
				// Remove pattern from our list if active patterns
				// runningDNSState.Patterns = append(runningDNSState.Patterns[:patternIndex], runningDNSState.Patterns[patternIndex+1:]...)
				// log.Printf("After removal, patterns are: %s\n", runningDNSState.Patterns)
				runningDNSServer.ServeMux.HandleRemove(pattern)
			} else {
				// https://play.golang.org/p/YSG7q7uQgv
				log.Printf("Retaining pattern %s in position %s\n", runningDNSServer.Patterns[i], j)
				runningDNSServer.Patterns[j] = runningDNSServer.Patterns[i]
				j++
			}
		}
		// Trim unwanted items off of slice
		log.Printf("j is %s\n", j)
		runningDNSServer.Patterns = runningDNSServer.Patterns[:j]
		log.Printf("After removal, patterns are: %s\n", runningDNSServer.Patterns)

		// If there are no more patterns assigned, stop server
		if len(runningDNSServer.Patterns) == 0 {
			log.Printf("Stopping server: %s\n", listenerKey)
			runningDNSServer.ShutdownChannel <- 0
			// Remove runningResolverKey from runningResolvers
			delete(runningDNSServers, listenerKey)
		}
	}
}

func dumpRunningDNSServers() {
	for _, runningDNSServer := range RunningDNSServers {
		log.Printf("Listener: \n", runningDNSServer.Listener.Key())
		log.Printf("  Patterns: \n", runningDNSServer.Patterns)
	}
}

func main() {
	// User-provided parameters
	// TODO support TSIG via /v1/resolvers api
	// var tsigName, tsigSecret string

	// Via environment variables
	// dnsListenTcp, ok := os.LookupEnv("YESDNS_DNS_LISTEN_TCP")
	// if ! ok { dnsListenTcp = "0.0.0.0:8053" }
	// dnsListenUdp, ok := os.LookupEnv("YESDNS_DNS_LISTEN_UDP")
	// if ! ok { dnsListenUdp = "0.0.0.0:8053" }
	httpListen, ok := os.LookupEnv("YESDNS_HTTP_LISTEN")
	if ! ok { httpListen = "0.0.0.0:8080" }
	dbDir, ok := os.LookupEnv("YESDNS_DB_DIR")
	if ! ok { dbDir = "./db/v1" }
	// Via command line
	// dnsListenTcp = *flag.String("dns-listen-tcp", dnsListenTcp, "IP address and TCP port to serve DNS on. Also env var YESDNS_DNS_LISTEN_TCP")
	// dnsListenUdp = *flag.String("dns-listen-udp", dnsListenUdp, "IP address and UDP port to serve DNS on. Also env var YESDNS_DNS_LISTEN_UDP")
	httpListen = *flag.String("http-listen", httpListen, "IP address and TCP port to serve HTTP on. Also env var YESDNS_HTTP_LISTEN")
	dbDir = *flag.String("db-dir", dbDir, "Directory to store Scribble database in. Also env var YESDNS_DB_DIR")
	flag.Parse()

	// Initialize global resolver list
	RunningDNSServers = make(map[string]DNSServerState)

	// Initialize database
	// TODO Possible traversal attack via dbDir?
	err, database := NewDatabase(dbDir)
	if err != nil {
		log.Printf("Could not open database %s\n", dbDir)
		return
	}

	syncResolversWithDatabase(database, RunningDNSServers)

	// Start up REST API
	go serveRestApi(httpListen, database)

	// Wait for process to be stopped by user
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Waiting forever for SIGINT OR SIGTERM")
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
