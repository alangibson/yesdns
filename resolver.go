package yesdns

// This file contains logic for spawning and killing DNS servers.

// Depends on:
// db.go/Database
import (
	"strings"
	"github.com/miekg/dns"
	"log"
)

type ResolverStore struct {
	Type 			string 	`json:"type"`
}

type Resolver struct {
	Id 				string				`json:"id"`
	Patterns 		[]string			`json:"patterns"`
	Store 			ResolverStore		`json:"store"`
	Listeners 		[]ResolverListener	`json:"listeners"`
	Forwarders		[]Forwarder			`json:"forwarders"`
	// We expect Database connection to match ResolverStore
	Database		*Database
}

// If an internal error occured (ie ServerFail), error will be set.
// If name not found (ie NXDomain), DnsMessage will be null.
//
// This function is potentially expensive because it can do 2 database lookups and a DNS request in the worst case.
func (r Resolver) Resolve(qType uint16, qName string) (error, *DnsMessage) {
	// TODO Type 255 (dns.TypeANY) means any/all records
	
	// Try normal resolution
	err, answerDnsMessage := r.Database.ReadResolverDnsMessage(r.Id, qType, qName)
	if err != nil {
		// We get err if we couldn't find record, which is not an error
	} else if answerDnsMessage != nil {
		// We found an answer, so return it
		return nil, answerDnsMessage
	}
	
	// Try wildcard if no result for exact match
	wildcardQname := qnameToWildcard(qName)
	// Try lookup again
	err, wildcardDnsMessage := r.Database.ReadResolverDnsMessage(r.Id, qType, wildcardQname)
	if err != nil {
		// We get err if we couldn't find record, which is not an error
	} else if wildcardDnsMessage != nil {
		// We found an answer, so return it
		// but first, we have to fix the Qname
		wildcardDnsMessage.Question[0].Qname = qName
		return nil, wildcardDnsMessage
	}
	
	return nil, nil
}

func (r Resolver) Forward(dnsMsg *dns.Msg) (error, *dns.Msg) {
	var responsDnsMsg *dns.Msg
	var exchangeErr error
	for _, forwarder := range r.Forwarders {
		log.Printf("DEBUG Querying forward %s with message \n%s\n", forwarder, dnsMsg)
		if exchangeErr, responsDnsMsg = forwarder.Forward(dnsMsg); exchangeErr != nil {
			// Hard error occured. Log a warning and (maybe) try other forwarders.
			log.Printf("WARN Failed to query forwarder %s. Error was: %s\n", forwarder, exchangeErr)
		} else if responsDnsMsg.Rcode == dns.RcodeSuccess {
			return nil, responsDnsMsg
		} else if responsDnsMsg.Rcode == dns.RcodeNameError && responsDnsMsg.RecursionAvailable {
			// TODO is this correct behavior?
			// Forwarder stated affirmatively that domain does not exist
			return nil, responsDnsMsg
		} // else continue on to next forwarder
	}
	// TODO is this correct behavior?
	// We did not get an affirmative answer, so just return the result from the last forward
	return exchangeErr, responsDnsMsg
}

// Replaces the first part of a Qname/domainname with *
//   hostname.some.example. -> *.some.example.
func qnameToWildcard(qName string) string {
	return "*." + strings.SplitN(qName, ".", 2)[1]
}
