package yesdns

// This file contains logic for spawning and killing DNS servers.

// Depends on:
// db.go/Database
// dns.go/handleDnsQuery
import (
	"log"
	"github.com/miekg/dns"
	"strings"
)

// Package-level shared variable
var RunningDNSServers map[string]DNSServerState

type DNSServerState struct {
	ServeMux 		*dns.ServeMux
	Patterns		[]string
	ShutdownChannel	chan int
	Listener		ResolverListener
}

type ResolverStore struct {
	Type 			string 	`json:"type"`
}

type ResolverListener struct {
	Net 			string	`json:"net"`
	Address			string	`json:"address"`
}

func (rl ResolverListener) Key() string {
	return rl.Address + "-" + rl.Net
}

type Resolver struct {
	Id 				string				`json:"id"`
	Patterns 		[]string			`json:"patterns"`
	Store 			ResolverStore		`json:"store"`
	Listeners 		[]ResolverListener	`json:"listeners"`
	// We expect Database connection to match ResolverStore
	Database		*Database
}

// If an internal error occured (ie ServerFail), error will be set.
// If name not found (ie NXDomain), DnsMessage will be null.
//
// This function is potentially expensive because it can do 2 database lookups and a DNS request in the worst case.
//
// TODO it would be better to have the client's full dns.Msg here in case we need to forward
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
		// TODO support multiple questions
		wildcardDnsMessage.Question[0].Qname = qName
		return nil, wildcardDnsMessage
	}

	// TODO Try forwarder if no answer for exact match
	
	return nil, nil
}

// Replaces the first part of a Qname/domainname with *
//   hostname.some.example. -> *.some.example.
func qnameToWildcard(qName string) string {
	return "*." + strings.SplitN(qName, ".", 2)[1]
}

// Starts and stops resolvers based on config in database.
// Maps are a 'reference type', so even though we appear to pass by value, we really just get a reference.
func SyncResolversWithDatabase(db *Database, runningDNSServers map[string]DNSServerState) {

	log.Printf("INFO Reloading DNS servers from database\n")

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
							log.Printf("DEBUG Found matching configured and running pattern (%s) in listener %s\n",
								configuredPattern, listenerKey)
							inRunningListener = true
							break
						}
					}

					// Do nothing if pattern already registered with handler.
					// Otherwise, create new handler and register pattern with running server.
					if inRunningListener {
						log.Printf("DEBUG Pattern %s already registered on listener %s\n",
							configuredResolver.Patterns, listenerKey)

						// Record that this listener+pattern combo was in the configuration
						// TODO refactor: this is copied from Resolver.Keys()
						keptKeys = append(keptKeys, listener.Key() + "-" + configuredPattern)
					} else {
						// There is already a running dns.Server for this listener
						// Update handlers to serve configuredResolver.Pattern
						log.Printf("INFO Adding pattern (%s) to running server %s\n",
							configuredResolver.Patterns, runningDNSServer)

						for _, configuredPattern := range configuredResolver.Patterns {
							
							// configuredResolver.Id
							runningDNSServer.ServeMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver))
							// Add this pattern to the list of patterns this server will handle
							runningDNSServer.Patterns = append(runningDNSServer.Patterns, configuredPattern)
							log.Printf("DEBUG After addition, patterns are: %s\n", runningDNSServer.Patterns)
							runningDNSServers[listenerKey] = runningDNSServer

							// Record that this listener+pattern combo was in the configuration
							// TODO refactor: this is copied from Resolver.Keys()
							keptKeys = append(keptKeys, listener.Key() + "-" + configuredPattern)
						}
					}
				}
			} else { // Server/Listener is not already running

				log.Printf("INFO Starting new server on %s %s with pattern '%s'\n",
					listener.Net, listener.Address, configuredResolver.Patterns)
				// Create new dns.Server
				// Each listener (protocol+interface+port combo) has its own ServeMux, and hence its
				// own patter. name space.
				var serveMux = dns.NewServeMux()
				var patterns []string
				for _, configuredPattern := range configuredResolver.Patterns {

					// Register a handler for pattern
					serveMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver))
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
				log.Printf("DEBUG Added running server %s with listener key %s and patterns %s\n",
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