package yesdns

// Depends on:
// resolver.go/SyncResolversWithDatabase
import (
	"log"
	"net/http"
	"encoding/json"
	"fmt"
	//"path/filepath"
)

// Runs REST API HTTP server forever.
//
// httpListenAddr: (string) interface and port to listen on
// database: (*Database) Reference to local database that stores DNS records.
func ServeRestApi(httpListenAddr string, database *Database, reloadChannel chan <- bool, tlsCertFile string, tlsKeyFile string) {
	http.HandleFunc("/v1/question", func(w http.ResponseWriter, r *http.Request) {
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
			log.Printf("DEBUG Saving %s\n", dnsRecord)
			if err := database.WriteDnsMessage(dnsRecord); err != nil {
				log.Printf("ERROR Error saving %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO return 204 No content
		} else if r.Method == http.MethodDelete {
			// TODO validate dnsRecord
			log.Printf("DEBUG Deleting %s\n", dnsRecord)
			if err := database.DeleteDnsMessage(dnsRecord); err != nil {
				log.Printf("ERROR Error deleting %s. Error was: %s\n", dnsRecord, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO Return 204 No Content
		} else {
			// TODO return json error message
			http.Error(w, fmt.Sprintf("Method %s not allowed for /v1/question\n", r.Method), http.StatusMethodNotAllowed)
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
		if r.Method == http.MethodPut {
			if err := database.WriteResolver(resolver); err != nil {
				log.Printf("ERROR Error writing %s. Error was: %s\n", resolver, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadChannel <- true
		} else if r.Method == http.MethodDelete {
			if err := database.DeleteResolver(resolver); err != nil {
				log.Printf("ERROR Error deleting %s. Error was: %s\n", resolver, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadChannel <- true
		} else {
			// TODO return json error message
			http.Error(w, fmt.Sprintf("Method %s not allowed for /v1/resolver\n", r.Method), http.StatusMethodNotAllowed)
		}
	})

	// Start serving REST API forever
	if tlsCertFile == "" || tlsKeyFile == "" {
		log.Printf("INFO Starting unsecured REST API listener on %s\n", httpListenAddr)
		log.Fatal(http.ListenAndServe(httpListenAddr, nil))
	} else {
		log.Printf("INFO Starting TLS REST API listener on %s\n", httpListenAddr)
		// tlsCertFile, _ := filepath.Abs(tlsCertFile)
		// tlsKeyFile, _ := filepath.Abs(tlsKeyFile)
		log.Fatal(http.ListenAndServeTLS(httpListenAddr, tlsCertFile, tlsKeyFile, nil))
	}
}
