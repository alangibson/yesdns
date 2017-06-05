FROM golang:1.7

WORKDIR /go/src/github.com/alangibson/yesdns
COPY . .

RUN go-wrapper download   # "go get -d -v ./..."
RUN go-wrapper install    # "go install -v ./..."

WORKDIR /go/src/github.com/alangibson/yesdns/cmd/yesdns
RUN go-wrapper install    # "go install -v ./..."

# Default HTTP port is 5380
# By convention, the 'default' resolver is on 53
EXPOSE 53 5380

ENTRYPOINT yesdns
