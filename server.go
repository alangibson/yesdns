package yesdns

import (
	"github.com/miekg/dns"
)

// Hold state of a single running DNS server.
// A Server is basically a combination of a Listener and a Resolver.
type ServerState struct {
	ServeMux 		*dns.ServeMux
	Patterns		[]string
	ShutdownChannel	chan int
	Listener		ResolverListener
	Resolver		*Resolver
}

func (s ServerState) HasPattern(pattern string) bool {
	for _, runningServerPattern := range s.Patterns {
		if pattern == runningServerPattern {
			return true
		}
	}
	return false
}

// TODO support in rest api: go serveDns(listener.Net, listener.Address, tsigName, tsigSecret)
// TODO should probably return a pointer
func NewServer(db *Database, configuredResolver *Resolver, listener ResolverListener) ServerState {
	// Each listener (protocol+interface+port combo) has its own ServeMux, and hence its
	// own pattern name space.
	var serveMux = dns.NewServeMux()
	// var patterns []string
	for _, configuredPattern := range configuredResolver.Patterns {
		// Register a handler for pattern
		serveMux.HandleFunc(configuredPattern, handleDnsQuery(db, configuredResolver))
		// patterns = append(patterns, configuredPattern)
		// Record that this listener+pattern combo was in the configuration
		// keptListenerPatternKeys = append(keptListenerPatternKeys, listenerPatternKey(listener.Key(), configuredPattern))
	}
	
	// Start up DNS listeners
	shutdownChannel := make(chan int)
	go serveDns(listener.Net, listener.Address, "", "", serveMux, shutdownChannel)
	
	return ServerState{ ShutdownChannel:shutdownChannel, ServeMux:serveMux, Patterns:configuredResolver.Patterns, Listener: listener, Resolver: configuredResolver }
}