package yesdns

// This package records and manages the state of running servers.

// Depends on:
// dns.go/handleDnsQuery
import (
	"github.com/miekg/dns"
	"log"
)

// Package-level shared variable
// Holds state of all running DNS servers
var RunningDNSServers = make(map[string]DNSServerState)

// Hold state of a single running DNS server
type DNSServerState struct {
	ServeMux 		*dns.ServeMux
	Patterns		[]string
	ShutdownChannel	chan int
	Listener		ResolverListener
}

func listenerPatternKey(listenerKey string, pattern string) string {
	return listenerKey + "-" + pattern
}

// Uses global variable RunningDNSServers.
func cleanUpRunningDNSServers(keptListenerPatternKeys []string) {
	// Stop all running DNS servers, or just remove patterns from them, that were not in configuration this time
	for listenerKey, runningDNSServer := range RunningDNSServers {
		log.Printf("DEBUG Before removals, patterns are: %s\n", runningDNSServer.Patterns)
		
		// If listenerKey not in keptKeys, remove pattern from listener
		// https://play.golang.org/p/YSG7q7uQgv
		j := 0
		for i := 0; i < len(runningDNSServer.Patterns); i++ {
			pattern := runningDNSServer.Patterns[i]
			runningKey := listenerPatternKey(listenerKey, pattern)
			inKeptKeys := false
			for _, keptKey := range keptListenerPatternKeys {
				log.Printf("DEBUG Comparing kept key '%s' == running key '%s'\n", keptKey, runningKey)
				if keptKey == runningKey {
					log.Printf("DEBUG Keeping %s\n", keptKey)
					inKeptKeys = true
				}
			}
			// Listener+pattern combo not in keptKeys, so remove it
			if ! inKeptKeys {
				log.Printf("DEBUG Removing pattern %s from running server %s\n", pattern, listenerKey)
				// Remove pattern from our list if active patterns
				runningDNSServer.ServeMux.HandleRemove(pattern)
			} else {
				log.Printf("DEBUG Retaining pattern %s in position %s\n", runningDNSServer.Patterns[i], j)
				runningDNSServer.Patterns[j] = runningDNSServer.Patterns[i]
				j++
			}
		}
		// Trim unwanted items off of slice
		runningDNSServer.Patterns = runningDNSServer.Patterns[:j]
		log.Printf("DEBUG After removal, patterns are: %s\n", runningDNSServer.Patterns)

		// If there are no more patterns assigned, stop server
		if len(runningDNSServer.Patterns) == 0 {
			log.Printf("Stopping server: %s\n", listenerKey)
			runningDNSServer.ShutdownChannel <- 0
			// Remove runningResolverKey from runningResolvers
			delete(RunningDNSServers, listenerKey)
		}
	}
}

// FIXME needs to be synchronized!
// Starts and stops resolvers based on config in database.
// Maps are a 'reference type', so even though we appear to pass by value, we really just get a reference.
// Uses global variable RunningDNSServers.
func SyncResolversWithDatabase(db *Database) {
	log.Printf("INFO Reloading DNS servers from database\n")

	// These are the listenerPatternKey() that we will keep running when done
	var keptListenerPatternKeys []string

	// TODO check error
	_, configuredResolvers := db.ReadAllResolvers()

	// Iterate over all resolvers configured in the database
	for _, configuredResolver := range configuredResolvers {

		// Iterate over configured listeners in each resolver and possibly start new ones
		for _, listener := range configuredResolver.Listeners {
			
			runningDNSServer, ok := RunningDNSServers[listener.Key()]

			if ok { // Server/Listener is already running

				// Make sure there is a handler attached to each server/listener for each pattern.
				for _, configuredPattern := range configuredResolver.Patterns {

					// See if pattern has already been added to running server/listener.
					inRunningListener := false
					for _, runningServerPattern := range runningDNSServer.Patterns {
						if configuredPattern == runningServerPattern {
							log.Printf("DEBUG Found matching configured and running pattern (%s) in listener %s\n",
								configuredPattern, listener.Key())
							inRunningListener = true
							break
						}
					}

					// Do nothing if pattern already registered with handler.
					// Otherwise, create new handler and register pattern with running server.
					if inRunningListener {
						// Listener for pattern is already registered with DNS server
						log.Printf("DEBUG Pattern %s already registered on listener %s\n",
							configuredResolver.Patterns, listener.Key())
						// Record that this listener+pattern combo was in the configuration
						keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
					} else {
						// There is already a running dns.Server for this listener, so just add query handler.
						log.Printf("INFO Adding pattern (%s) to running server %s\n",
							configuredResolver.Patterns, runningDNSServer)
						// Update handlers to serve configuredResolver.Pattern
						for _, configuredPattern := range configuredResolver.Patterns {
							runningDNSServer.ServeMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver))
							// Add this pattern to the list of patterns this server will handle
							runningDNSServer.Patterns = append(runningDNSServer.Patterns, configuredPattern)
							log.Printf("DEBUG After addition, patterns are: %s\n", runningDNSServer.Patterns)
							RunningDNSServers[listener.Key()] = runningDNSServer
							// Record that this listener+pattern combo was in the configuration
							keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
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
					keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
				}

				// Start up DNS listeners
				// TODO support in rest api: go serveDns(listener.Net, listener.Address, tsigName, tsigSecret)
				shutdownChannel := make(chan int)
				go serveDns(listener.Net, listener.Address, "", "", serveMux, shutdownChannel)
				// Save shutdown channel for later use
				runningDNSServer.ShutdownChannel = shutdownChannel

				// Record new server/listener
				RunningDNSServers[listener.Key()] = DNSServerState{
					ShutdownChannel:shutdownChannel, ServeMux:serveMux, Patterns:patterns, Listener: listener }
				log.Printf("DEBUG Added running server %s with listener key %s and patterns %s\n",
					RunningDNSServers[listener.Key()], listener.Key(), patterns)
			}
		}
	}

	log.Printf("Keeping keys: %s\n", keptListenerPatternKeys)
	cleanUpRunningDNSServers(keptListenerPatternKeys)
}