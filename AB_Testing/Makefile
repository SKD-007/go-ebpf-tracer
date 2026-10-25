.PHONY: all build-client build-s1 build-s2A build-s2B

all: build-client build-s1 build-s2A build-s2B

build-client: client.go
	go build -o client client.go

build-s1: server1.go
	go build -o server1 server1.go

build-s2A: server2A.go
	go build -o server2A server2A.go

build-s2B: server2B.go
	go build -o server2B server2B.go
