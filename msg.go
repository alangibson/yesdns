package yesdns

// Internal representation of messages for REST API and database.

type DnsHeader struct {
    // Id                 uint16    `json:"id"`
    // Response           bool      `json:"response"`
    // Opcode             int       `json:"opcode"`
    // RecursionDesired   bool      `json:"recursion_desired"`
    Authoritative      bool      `json:"authoritative"`
    Truncated          bool      `json:"truncated"`
    RecursionAvailable bool      `json:"recursion_available"`
    Zero               bool      `json:"zero"`
    AuthenticatedData  bool      `json:"authenticated_data"`
    CheckingDisabled   bool      `json:"checking_disabled"`
    Rcode              int       `json:"rcode"`
}

type DnsRR struct {
    Name  string      `json:"name"`
    Type  uint16      `json:"type"`
    Class uint16      `json:"class"`
    Ttl   uint32      `json:"ttl"`
    Rdata interface{} `json:"rdata"`
}

type DnsQuestion struct {
    Qname  string	`json:"qname"`
    Qtype  uint16	`json:"qtype"`
    Qclass uint16	`json:"qclass"`
}

type DnsMessage struct {
    Resolvers  []string		`json:"resolvers"`
    MsgHdr     DnsHeader	`json:"header"`
    Question   []DnsQuestion	`json:"question"`
    Answer     []DnsRR		`json:"answer"`
    Ns         []DnsRR		`json:"ns"`
    Extra      []DnsRR		`json:"extra"`
}
