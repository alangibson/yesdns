package yesdns

// This package records and manages the state of running servers.

// Depends on:
// dns.go/handleDnsQuery
// server.go
// listener.go
import (
	"log"
)

func listenerPatternKey(listenerKey string, pattern string) string {
	return listenerKey + "-" + pattern
}

func addServers(runningServers map[string]*ServerState, db *Database, configuredResolvers []*Resolver) []string {
	
	// These are the listenerPatternKey() that we will keep running when done
	var keptListenerPatternKeys []string
	
	// Iterate over all resolvers configured in the database
	for _, configuredResolver := range configuredResolvers {

		// Iterate over configured listeners in each resolver and possibly start new ones
		for _, listener := range configuredResolver.Listeners {
			
			// Get the running DNS server that corresponds to the current configured listener
			runningServer, ok := runningServers[listener.Key()]
			
			// This block ensures that there is a Server running for every resolver configured in the db
			if ok { // Server is already running
				
				// Update running DNS server with fresh Forwarder config from the db
				// NOTE: We can not currently do runningServer.Resolver = configuredResolver because handleDnsQuery
				//       holds a reference to the original configuredResolver it was created with.
				// 		 If we ever want to reload the entire Resolver config, we will need to pass a reference to
				// 		 ServerState to handleDnsQuery callback.
				log.Printf("DEBUG Forwarders for resolver %s listener %s were: %s, will be %s\n",
					runningServer.Resolver.Id, listener.Key(), runningServer.Resolver.Forwarders, configuredResolver.Forwarders)
				runningServer.Resolver.Forwarders = configuredResolver.Forwarders
				
				// Make sure there is a handler attached to each server/listener for each pattern.
				for _, configuredPattern := range configuredResolver.Patterns {
					// See if pattern has already been added to running server/listener.
					// Do nothing if pattern already registered with handler.
					// Otherwise, create new handler and register pattern with running server.
					if inRunningListener := runningServer.HasPattern(configuredPattern); inRunningListener {
						// Listener for pattern is already registered with DNS server
						log.Printf("DEBUG Pattern %s already registered on listener %s\n",
							configuredPattern, listener.Key())
						// Record that this listener+pattern combo was in the configuration
						keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
					} else {
						// There is already a running dns.Server for this listener, so just add query handler.
						log.Printf("DEBUG Adding pattern (%s) to running server %s\n",
							configuredResolver.Patterns, runningServer)
						// Update handlers to serve configuredResolver.Pattern
						for _, configuredPattern := range configuredResolver.Patterns {
							runningServer.ServeMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver))
							// Add this pattern to the list of patterns this server will handle
							runningServer.Patterns = append(runningServer.Patterns, configuredPattern)
							log.Printf("DEBUG After addition, patterns are: %s\n", runningServer.Patterns)
							runningServers[listener.Key()] = runningServer
							// Record that this listener+pattern combo was in the configuration
							keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
						}
					}
				}
			} else { // Server/Listener is not already running
				log.Printf("INFO Starting new server on %s with pattern '%s'\n", listener, configuredResolver.Patterns)
				// Start up a new server and save a reference to it
				runningServers[listener.Key()] = NewServer(db, configuredResolver, listener)
				// Record the listener+pattern combos we kept
				for _, configuredPattern := range configuredResolver.Patterns {
					keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
				}
				log.Printf("DEBUG Added running server %s with listener key %s and patterns %s\n",
					runningServers[listener.Key()], listener.Key(), configuredResolver.Patterns)
			}
		}
	}
	return keptListenerPatternKeys
}

// Uses global variable RunningDNSServers.
func cleanUpServers(runningServers map[string]*ServerState, keptListenerPatternKeys []string) {
	// Stop all running DNS servers, or just remove patterns from them, that were not in configuration this time
	for listenerKey, runningServer := range runningServers {
		log.Printf("DEBUG Before removals, patterns are: %s\n", runningServer.Patterns)
		
		// If listenerKey not in keptKeys, remove pattern from listener
		// https://play.golang.org/p/YSG7q7uQgv
		j := 0
		for i := 0; i < len(runningServer.Patterns); i++ {
			pattern := runningServer.Patterns[i]
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
				runningServer.ServeMux.HandleRemove(pattern)
			} else {
				log.Printf("DEBUG Retaining pattern %s in position %s\n", runningServer.Patterns[i], j)
				runningServer.Patterns[j] = runningServer.Patterns[i]
				j++
			}
		}
		// Trim unwanted items off of slice
		runningServer.Patterns = runningServer.Patterns[:j]
		log.Printf("DEBUG After removal, patterns are: %s\n", runningServer.Patterns)

		// If there are no more patterns assigned, stop server
		if len(runningServer.Patterns) == 0 {
			log.Printf("INFO Stopping server: %s\n", listenerKey)
			runningServer.ShutdownChannel <- 0
			// Remove runningResolverKey from runningResolvers
			delete(runningServers, listenerKey)
		}
	}
}

// Starts and stops resolvers based on config in database.
// Maps are a 'reference type', so even though we appear to pass by value, we really just get a reference.
// Uses global variable RunningDNSServers.
func SyncServersWithDatabase(db *Database, reloadChannel chan bool) {
	
	// Holds state of all running DNS servers indexed by Listener.Key()
	runningServers := make(map[string]*ServerState)
	
	for {
		log.Printf("DEBUG Reloading DNS servers from database\n")
		
		if err, configuredResolvers := db.ReadAllResolvers(); err != nil {
			log.Printf("WARN Could not load any resolvers because: %s\n", err)
		} else {
			keptListenerPatternKeys := addServers(runningServers, db, configuredResolvers)
			cleanUpServers(runningServers, keptListenerPatternKeys)
		}
		
		// Block and wait for signal on reload channel
		<- reloadChannel
	}
}