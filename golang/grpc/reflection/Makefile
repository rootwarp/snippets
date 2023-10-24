.PHONY: proto

proto:
	@protoc -I./proto \
		--go_out ./ --go_opt paths=import \
		--go-grpc_out ./ --go-grpc_opt paths=import \
		proto/agent/*.proto

	@protoc -I./proto \
		--go_out ./ --go_opt paths=import \
		--go-grpc_out ./ --go-grpc_opt paths=import \
		proto/plugin/*.proto


