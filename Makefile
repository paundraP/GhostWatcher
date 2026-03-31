PROTOC_GEN_PATH := $(shell go env GOPATH)/bin:$(PATH)

.PHONY: proto tidy test build run-server run-agent

proto:
	PATH="$(PROTOC_GEN_PATH)" protoc --go_out=. --go-grpc_out=. --go_opt=module=ghostwatcher --go-grpc_opt=module=ghostwatcher proto/ghostwatcher.proto

tidy:
	go mod tidy

test:
	go test ./...

build:
	go build ./...

run-server:
	go run ./cmd/server -listen :50051 -db-path ./ghostwatcher.db

run-agent:
	go run ./cmd/agent -server localhost:50051 -events 45 -interval 200ms
