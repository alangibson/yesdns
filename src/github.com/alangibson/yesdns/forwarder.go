package yesdns

import (
	"github.com/miekg/dns"
	"log"
)

type Forwarder struct {
	Address	string	`json:"address"`
	Database		*Database
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

func ForwardToAll(dnsMsg *dns.Msg, database *Database) (error, *dns.Msg) {
	err, forwarders := database.ReadAllForwarders()
	if err != nil {
		log.Printf("ERROR Failed to load forwarders. Error was: %s\n", err)
		return err, nil
	}
	var responsDnsMsg *dns.Msg
	var exchangeErr error
	for _, forwarder := range forwarders {
		log.Printf("DEBUG Sending DNS message %s to forward %s\n", dnsMsg, forwarder)
		exchangeErr, responsDnsMsg = forwarder.Forward(dnsMsg)
		// Interpret return code to see if we should go to next forward
		if responsDnsMsg.Rcode == dns.RcodeSuccess {
			return nil, responsDnsMsg
		} else if responsDnsMsg.Rcode == dns.RcodeNameError && responsDnsMsg.RecursionAvailable {
			// TODO is this correct behavior?
			// Forwarder stated affirmatively that domain does not exist
			return nil, responsDnsMsg
		} // else continue on to next forwarder
	}
	// TODO is this correct behavior?
	// We did not get an affirmative answer, so just return the result from the last forward
	return exchangeErr, responsDnsMsg
}