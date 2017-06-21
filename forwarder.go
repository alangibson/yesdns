package yesdns

import (
	"github.com/miekg/dns"
)

type Forwarder struct {
	Net 	string	`json:"net"`
	Address	string	`json:"address"`
}

// Returns nil dns.Msg on hard error
func (forwarder Forwarder) Forward(dnsMsg *dns.Msg) (error, *dns.Msg) {
	dnsClient := dns.Client{}
	responsDnsMsg, _, err := dnsClient.Exchange(dnsMsg, forwarder.Address)
	if err != nil {
		// Hard error, so return it
		return err, nil
	}
	return nil, responsDnsMsg
}
