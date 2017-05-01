YesDNS
======

YesDNS is an obsequious DNS server that tells you exactly want you want to hear.

YesDNS responds to DNS queries with DNS messages provided to it by a REST interface. It returns only what you tell it to, and absolutely anything you tell it to, without modificaiton.

YesDNS is intended for testing and quickly standing up ephemeral environments.

YesDNS does not yet implement any sort of security. DO NOT expose YesDNS to the outside world.

Usage
-----

Run

    git clone https://github.com/alangibson/yesdns.git
    cd yesdns/src
    go build && ./yesdns &
    curl -v -X PUT -d@../../test/data/A.json localhost:8080/v1/message
    dig @localhost -p 8053 some.domain. A

Output

    ; <<>> DiG 9.10.3-P4-Ubuntu <<>> @localhost -p 8053 some.domain. A
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22578
    ;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;some.domain.			IN	A

    ;; ANSWER SECTION:
    some.domain.		10	IN	A	1.2.3.4

    ;; AUTHORITY SECTION:
    some.domain.		0	IN	NS	ns1.some.domain.

    ;; ADDITIONAL SECTION:
    some.domain.		10	IN	TXT	"" "" "Text line 1 of 2" "Text line 2 of 2"

    ;; Query time: 1 msec
    ;; SERVER: 127.0.0.1#8053(127.0.0.1)
    ;; WHEN: Mon Apr 17 18:57:51 CEST 2017
    ;; MSG SIZE  rcvd: 155

Testing
-------

    ./test/test.sh

Caveats
-------

- No REST API security (yet)
- No recursion support (yet)
- No DNSSEC support (yet)
- No zone transfer support (yet)

References
----------

DNS Messages: http://www.zytrax.com/books/dns/ch15/
