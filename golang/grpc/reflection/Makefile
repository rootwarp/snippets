.PHONY: proto agent plugin

agent:
	go build -o build/agent ./client/agent/main.go

plugin:
	go build -o build/plugin ./client/plugin/main.go

proto:
	@protoc -I./proto \
		--go_out ./ --go_opt paths=import \
		--go-grpc_out ./ --go-grpc_opt paths=import \
		proto/agent/*.proto

	@protoc -I./proto \
		--go_out ./ --go_opt paths=import \
		--go-grpc_out ./ --go-grpc_opt paths=import \
		proto/plugin/*.proto
