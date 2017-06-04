#!/bin/bash

GOPATH=${GOPATH:-/tmp/gopath}
export GOPATH

YESDNS_PID=0

set_up() {
  set -e

  # Set up GOPATH
  echo GOPATH is $GOPATH

  # 'go get' requirements
  echo Installing requirements in $GOPATH
  rm -fr "$GOPATH"
  go get github.com/nanobox-io/golang-scribble
  go get github.com/miekg/dns

  # Start YesDNS
  rm -fr db/
  go install github.com/alangibson/yesdns
  go install github.com/alangibson/yesdns/cmd/yesdns
  ./bin/yesdns > yesdns.log 2>&1 &
  YESDNS_PID=$!
  echo YesDNS pid is $YESDNS_PID
  sleep 2

  set +e
}

tear_down() {
  echo Killing YesDNS with pid $YESDNS_PID
  kill $YESDNS_PID
}
trap tear_down EXIT

assert_exit_ok() {
  if [ $1 -ne 0 ]; then
    echo "assert_exit_ok failed. Aborting."
    exit 1
  else
    echo "assert_exit_ok passed."
  fi
}

assert_exit_nok() {
  if [ $1 -eq 0 ]; then
    echo "assert_exit_nok failed. Aborting."
    exit 1
  else
    echo "assert_exit_n ok passed."
  fi
}

assert_dig_ok() {
  dig $1 -p $2 $3 $4
  dig +short $1 -p $2 $3 $4 | sed '/^;;/ d' | grep -v -e '^$' > /dev/null
  assert_exit_ok $?
}

set_up

echo //////////////////////////////////////////////////////////////////////////
echo // Test resolver startup
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/resolvers/resolver-0.0.0.0:8054.json localhost:8080/v1/resolver
nc -z -v localhost 8054
assert_exit_ok $?

echo //////////////////////////////////////////////////////////////////////////
echo // Test resolver stop
echo //////////////////////////////////////////////////////////////////////////
curl -v -X DELETE -d@./test/data/resolvers/resolver-0.0.0.0:8054.json localhost:8080/v1/resolver
nc -z -v localhost 8054
assert_exit_nok $?

echo //////////////////////////////////////////////////////////////////////////
echo // Test A Record
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/resolvers/default-0.0.0.0:8056.json localhost:8080/v1/resolver
curl -v -X PUT -d@./test/data/A-default.json localhost:8080/v1/message
assert_dig_ok @localhost 8056 hostname.example. A

echo //////////////////////////////////////////////////////////////////////////
echo // Test SOA Record
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/resolvers/default-0.0.0.0:8056.json localhost:8080/v1/resolver
curl -v -X PUT -d@./test/data/SOA.json localhost:8080/v1/message
assert_dig_ok @localhost 8056 some.domain. SOA

echo //////////////////////////////////////////////////////////////////////////
echo // Test Wildcard Lookup
echo //////////////////////////////////////////////////////////////////////////
curl -v -X PUT -d@./test/data/resolvers/default-0.0.0.0:8056.json localhost:8080/v1/resolver
curl -v -X PUT -d@./test/data/A-wildcard.json localhost:8080/v1/message
assert_dig_ok @localhost 8056 notreal.some.example. A

# echo //////////////////////////////////////////////////////////////////////////
# echo // Test Forwarding
# echo //////////////////////////////////////////////////////////////////////////
# curl -v -X PUT -d@./test/data/forwarder/forwarder-8.8.8.8.json localhost:8080/v1/forwarder
# assert_dig_ok @localhost 8063 www.google.com. A
