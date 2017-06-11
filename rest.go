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
	Resolvers  []string			`json:"resolvers"`
	MsgHdr     DnsHeader		`json:"msg_hdr"`
	Question   []DnsQuestion	`json:"question"`
	Answer     []DnsRR			`json:"answer"`
	Ns         []DnsRR			`json:"ns"`
	Extra      []DnsRR			`json:"extra"`
}

// Runs REST API HTTP server forever.
//
// httpListenAddr: (string) interface and port to listen on
// database: (*Database) Reference to local database that stores DNS records.
func ServeRestApi(httpListenAddr string, database *Database, reloadChannel chan <- bool, tlsCertFile string, tlsKeyFile string) {
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
			reloadChannel <- true
		} else if r.Method == http.MethodDelete {
			if err := database.DeleteResolver(resolver); err != nil {
				log.Printf("Error deleting %s. Error was: %s\n", resolver, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadChannel <- true
		} else {
			msg := fmt.Sprintf("Method %s not allowed for /v1/resolver\n", r.Method)
			// TODO return json error message
			http.Error(w, msg, http.StatusMethodNotAllowed)
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
