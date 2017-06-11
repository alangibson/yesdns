package yesdns

// Depends on:
// resolver.go/
import (
	"github.com/nanobox-io/golang-scribble"
	"log"
	"strconv"
	"encoding/json"
	"bytes"
)

//
// Database interface
//

type Database struct {
	db	*scribble.Driver
}

func NewDatabase(scribbleDbDir string) (error, *Database) {
	db, err := scribble.New(scribbleDbDir, nil)
	if err != nil {
		return err, nil
	}
	database := Database{db: db}
	return nil, &database
}

func (d Database) WriteDnsMessage(dnsRecord DnsMessage) error {
	log.Printf("DEBUG Saving %s to db\n", dnsRecord)

	// We create records for every resolver
	for _, resolverId := range dnsRecord.Resolvers {
		// We have 1 document in the db for every entry in Question section
		for _, question := range dnsRecord.Question {
			key := resolverId + "/" + strconv.Itoa(int(question.Qtype))
			err := d.db.Write(key, question.Qname, dnsRecord)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (d Database) WriteResolver(resolver Resolver) error {
	err := d.db.Write("resolvers", resolver.Id, resolver)
	return err
}

func (d Database) ReadDnsMessage(dnsRecord DnsMessage) (error, DnsMessage) {
	log.Printf("DEBUG Querying DNS Record %s\n", dnsRecord)
	question := dnsRecord.Question[0]
	returnDnsRecord := DnsMessage{}
	// TODO look up by resolver.id/question.qtype
	err := d.db.Read(strconv.Itoa(int(question.Qtype)), question.Qname, &returnDnsRecord)
	return err, returnDnsRecord
}

func (d Database) ReadResolverDnsMessage(resolverId string, qtype uint16, qname string) (error, *DnsMessage) {
	returnDnsRecord := DnsMessage{}
	key := resolverId + "/" + strconv.Itoa(int(qtype))
	err := d.db.Read(key, qname, &returnDnsRecord)
	return err, &returnDnsRecord
}

func (d *Database) ReadAllResolvers() (error, []*Resolver) {
	jsonStrings, err := d.db.ReadAll("resolvers")
	if len(jsonStrings) == 0 {
		return err, nil
	}
	var resolvers []*Resolver
	for _, jsonString := range jsonStrings {
		var resolver *Resolver
		if err := json.NewDecoder(bytes.NewBufferString(jsonString)).Decode(&resolver); err != nil {
			log.Printf("WARN Could not decode json: %s\n", err)
		} else {
			resolver.Database = d
			resolvers = append(resolvers, resolver)
		}
	}
	return err, resolvers
}

func (d Database) DeleteDnsMessage(dnsRecord DnsMessage) error {
	log.Printf("DEBUG Deleting DNS Record %s\n", dnsRecord)
	question := dnsRecord.Question[0]
	err := d.db.Delete(strconv.Itoa(int(question.Qtype)), question.Qname)
	return err
}

func (d Database) DeleteResolver(resolver Resolver) error {
	log.Printf("DEBUG Deleting resolver %s\n", resolver.Id)
	err := d.db.Delete("resolvers", resolver.Id)
	return err
}

