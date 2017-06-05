package yesdns

import (
	"github.com/miekg/dns"
	"log"
)

type Forwarder struct {
	Net 	string	`json:"net"`
	Address	string	`json:"address"`
}

func (forwarder Forwarder) Forward(dnsMsg *dns.Msg) (error, *dns.Msg) {
	log.Printf("DEBUG Sending DNS message %s to forward %s\n", dnsMsg, forwarder)
	dnsClient := dns.Client{}
	responsDnsMsg, _, err := dnsClient.Exchange(dnsMsg, forwarder.Address)
	if err != nil {
		// Hard error, so return it
		return err, nil
	}
	return nil, responsDnsMsg
}
