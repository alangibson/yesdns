#!/bin/bash

##
## Set Up
##

# Set up GOPATH
GOPATH=${GOPATH:-/tmp/gopath}
export GOPATH
echo GOPATH is $GOPATH

# 'go get' requirements
echo Installing requirements in $GOPATH
go get github.com/nanobox-io/golang-scribble
go get github.com/miekg/dns

# Start YesDNS
pushd ./src/yesdns
go build && ./yesdns &
YESDNS_PID=$!
echo YesDNS pid is $YESDNS_PID
popd

echo //////////////////////////////////////////////////////////////////////////
echo // Test A Record
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/A.json localhost:8080/v1/message
dig @localhost -p 8053 some.domain. A
echo Dig exit code was $?

echo //////////////////////////////////////////////////////////////////////////
echo // Test SOA Record
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/SOA.json localhost:8080/v1/message
dig @localhost -p 8053 some.domain. SOA
echo Dig exit code was $?

##
## Tear Down
##

echo Killing YesDNS with pid $YESDNS_PID
kill $YESDNS_PID
rm -fr /tmp/gopath