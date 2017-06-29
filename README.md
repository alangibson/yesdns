YesDNS
======

YesDNS is an obsequious DNS server that tells you exactly want you want to hear.

YesDNS responds to DNS queries with DNS messages provided to it by a REST interface. It returns only what you tell it to, and absolutely anything you tell it to, without modificaiton.

YesDNS is intended for testing and quickly standing up ephemeral environments.

YesDNS does not yet implement any sort of security. DO NOT expose YesDNS to the outside world.

Usage
-----

Run from source

    export GOPATH=/tmp/gopath
    go get github.com/alangibson/yesdns
    go install github.com/alangibson/yesdns/cmd/yesdns
    $GOPATH/bin/yesdns &
    curl -v -X PUT -d@"$GOPATH/src/github.com/alangibson/yesdns/test/data/resolvers/default-0.0.0.0-8053.json" localhost:5380/v1/resolver
    curl -v -X PUT -d@"$GOPATH/src/github.com/alangibson/yesdns/test/data/A.json" localhost:5380/v1/question
    dig @localhost -p 8053 some.example.com A
    ; <<>> DiG 9.10.3-P4-Ubuntu <<>> @localhost -p 8053 some.example.com A
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53579
    ;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
    ;; WARNING: recursion requested but not available
    
    ;; QUESTION SECTION:
    ;some.example.com.		IN	A
    
    ;; ANSWER SECTION:
    some.example.com.	10	IN	A	1.2.3.4
    
    ;; AUTHORITY SECTION:
    some.example.com.	0	IN	NS	ns1.example.com.
    
    ;; ADDITIONAL SECTION:
    some.example.com.	10	IN	TXT	"" "" "Text line 1 of 2" "Text line 2 of 2"
    
    ;; Query time: 0 msec
    ;; SERVER: 127.0.0.1#8053(127.0.0.1)
    ;; WHEN: Thu Jun 29 10:39:23 CEST 2017
    ;; MSG SIZE  rcvd: 175


Run with TLS

    openssl genrsa -out server.key 2048
    openssl ecparam -genkey -name secp384r1 -out server.key
    openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650 -subj "/C=US/ST=TX/L=Austin/O=YesDNS/CN=localhost"

    yesdns -http-listen=:53443 -tls-cert-file=server.crt -tls-key-file=server.key

Run via Docker

    docker run -d --name=yesdns -p 8053:8053/udp -p 8053:8053/tcp -p 5380:5380 alangibson/yesdns

Testing
-------

    ./test/test.sh

Resolution Algorithm 
--------------------

- Receive a DNS Question on a Listener.
- Look up exact matching record in database by Qtype and Qname
  - Return Answer if found
- Otherwise, substitute wildcard (*) for leftmost element in Qname and repeat lookup
      Example: hostname.example.com. -> *.example.com.
  - Return Answer if found and Name field provided
  - Return Answer with name set to Qname if found and Name field not provided
- Return NxDomain if no Forward configured
- Otherwise, send request to Forward if configured
  - If failure while forwarding, return ServFail
  - Return Answer from Forward if Forward returned positive response
- Otherwise, return NXDomain

Caveats
-------

- No REST API security (yet)
- Only supports Question OpCode (for now)
- Only supports IN Qclass (for now)
- Wildcards are not RFC4592 compliant, and only partially RFC1034 compliant
  - i.e. A.X.COM is matched by *.X.COM, but not *.A.X.COM
- Only supports 1 question per message, [like everyone else](https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query).
- User cannot set the following response header fields: Id, RecursionDesired, Opcode, Response, RecursionAvailable
- No recursion support
- No DNSSEC support
- No zone transfer support
- No Dynamic Update (RFC2136) support
- No DNS over TLS (RFC7858) support
- No caching 

References
----------

- [DNS Messages](http://www.zytrax.com/books/dns/ch15/)
- [RFC1034](https://tools.ietf.org/html/rfc1034)
- [RFC2136](https://tools.ietf.org/html/rfc2136)
- [RFC4592](https://tools.ietf.org/html/rfc4592)
