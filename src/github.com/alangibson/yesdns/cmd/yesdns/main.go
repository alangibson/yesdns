package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"log"
	"github.com/alangibson/yesdns"
)

func dumpRunningDNSServers() {
	for _, runningDNSServer := range yesdns.RunningDNSServers {
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
	yesdns.RunningDNSServers = make(map[string]yesdns.DNSServerState)

	// Initialize database
	// TODO Possible traversal attack via dbDir?
	err, database := yesdns.NewDatabase(dbDir)
	if err != nil {
		log.Printf("Could not open database %s\n", dbDir)
		return
	}

	yesdns.SyncResolversWithDatabase(database, yesdns.RunningDNSServers)

	// Start up REST API
	go yesdns.ServeRestApi(httpListen, database)

	// Wait for process to be stopped by user
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Waiting forever for SIGINT OR SIGTERM")
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
