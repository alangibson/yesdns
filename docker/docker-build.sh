#!/usr/bin/env bash

# Usage:
#   cd $GOPATH/src/github.com/alangibson/yesdns/docker
#   sudo GOPATH="$GOPATH" ./docker-build.sh

YESDNS_VERSION=$(git rev-parse --abbrev-ref HEAD)

go get github.com/nanobox-io/golang-scribble
go get github.com/miekg/dns
go get github.com/alangibson/yesdns

export CGO_ENABLED=0
go install github.com/alangibson/yesdns
go install github.com/alangibson/yesdns/cmd/yesdns

cp $GOPATH/bin/yesdns yesdns

docker build --rm --tag=alangibson/yesdns:$YESDNS_VERSION --tag=alangibson/yesdns:latest .

rm yesdns
