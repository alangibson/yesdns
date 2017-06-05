package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"log"
	"github.com/alangibson/yesdns"
)

func main() {
	// User-provided parameters
	// TODO support TSIG via /v1/resolvers api
	// var tsigName, tsigSecret string

	// Via environment variables
	httpListen, ok := os.LookupEnv("YESDNS_HTTP_LISTEN")
	if ! ok { httpListen = "0.0.0.0:5380" }
	dbDir, ok := os.LookupEnv("YESDNS_DB_DIR")
	if ! ok { dbDir = "./db/v1" }
	// Via command line
	httpListen = *flag.String("http-listen", httpListen, "IP address and TCP port to serve HTTP on. Also env var YESDNS_HTTP_LISTEN")
	dbDir = *flag.String("db-dir", dbDir, "Directory to store Scribble database in. Also env var YESDNS_DB_DIR")
	flag.Parse()

	// Initialize database
	// TODO Possible traversal attack via dbDir?
	err, database := yesdns.NewDatabase(dbDir)
	if err != nil {
		log.Printf("Could not open database %s\n", dbDir)
		return
	}

	// Sending value to this channel reloads resolvers from db
	reloadChannel := make(chan bool)
	
	// Start up resolver manager
	go yesdns.SyncResolversWithDatabase(database, reloadChannel)

	// Start up REST API
	go yesdns.ServeRestApi(httpListen, database, reloadChannel)

	// Wait for process to be stopped by user
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Waiting forever for SIGINT OR SIGTERM")
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
