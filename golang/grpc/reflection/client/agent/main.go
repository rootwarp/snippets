package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	//"google.golang.org/protobuf/encoding/protojson"

	"github.com/rootwarp/snippets/golang/grpc/reflection/proto/agent"
)

type reflectionHandler struct {
	inputSpecs  map[string]map[string]*desc.MessageDescriptor
	outputSpecs map[string]map[string]*desc.MessageDescriptor
}

func (r *reflectionHandler) Query(ctx context.Context, name, address string, port int) error {
	fmt.Println("Query")

	host := fmt.Sprintf("%s:%d", address, port)
	conn, err := grpc.Dial(host, grpc.WithInsecure())
	if err != nil {
		return err
	}

	defer conn.Close()

	reflectCli := grpc_reflection_v1.NewServerReflectionClient(conn)
	reflectInfoCli, err := reflectCli.ServerReflectionInfo(ctx)

	listReq := grpc_reflection_v1.ServerReflectionRequest_ListServices{}
	reflectReq := grpc_reflection_v1.ServerReflectionRequest{
		Host:           host,
		MessageRequest: &listReq,
	}

	err = reflectInfoCli.Send(&reflectReq)
	if err != nil {
		return err
	}

	reflectResp, err := reflectInfoCli.Recv()
	if err != nil {
		return err
	}

	listServiceResp := reflectResp.GetListServicesResponse()
	services := listServiceResp.GetService()

	var findService *grpc_reflection_v1.ServiceResponse
	for _, service := range services {
		fmt.Println("service", service.Name)
		if service.Name == name {
			findService = service
		}
	}

	if findService == nil {
		return fmt.Errorf("cannot find %s", name)
	}

	fmt.Println("found", findService)

	// List functions
	grpcReflectCli := grpcreflect.NewClientAuto(ctx, conn)
	serviceDesc, err := grpcReflectCli.ResolveService(name)
	if err != nil {
		return err
	}

	methods := serviceDesc.GetMethods()

	if r.inputSpecs == nil {
		r.inputSpecs = map[string]map[string]*desc.MessageDescriptor{}
	}

	if r.outputSpecs == nil {
		r.outputSpecs = map[string]map[string]*desc.MessageDescriptor{}
	}

	for _, method := range methods {
		fmt.Println("*", method.GetName())

		in := method.GetInputType()
		inFields := in.GetFields()
		fmt.Println(inFields)

		out := method.GetOutputType()
		outFields := out.GetFields()
		fmt.Println(outFields)

		if r.inputSpecs[name] == nil {
			r.inputSpecs[name] = map[string]*desc.MessageDescriptor{}
		}

		if r.outputSpecs[name] == nil {
			r.outputSpecs[name] = map[string]*desc.MessageDescriptor{}
		}

		r.inputSpecs[name][method.GetName()] = in
		r.outputSpecs[name][method.GetName()] = out
	}

	return nil
}

func (r *reflectionHandler) Inspection(ctx context.Context, serviceName, functionName string) error {
	fmt.Println("Inspection", serviceName, functionName)

	inDesc := r.inputSpecs[serviceName][functionName]
	desc := inDesc.AsDescriptorProto().ProtoReflect().Descriptor()
	descProto := protodesc.ToDescriptorProto(desc)

	d, err := json.Marshal(descProto)
	if err != nil {
		return err
	}

	fmt.Println("**************************")
	fmt.Println("json", string(d))

	// Reverse
	newDescProto := descriptorpb.DescriptorProto{}
	err = json.Unmarshal(d, &newDescProto)
	if err != nil {
		return err
	}

	fmt.Println("unmarshal", newDescProto.ProtoReflect().Descriptor())

	return nil
}

type registrationServer struct {
	agent.UnimplementedRegistrationServiceServer
}

func (s *registrationServer) RegisterPlugin(ctx context.Context, in *agent.RegisterRequest) (*agent.RegisterResponse, error) {
	fmt.Println("Register", in.Name, in.Address, in.Port)

	// TODO: Do reflection process
	err := r.Query(ctx, in.Name, in.Address, int(in.Port))
	fmt.Println("Query", err)
	// - Connect
	// - Get Service
	// - Get functions and parameters
	//
	err = r.Inspection(ctx, in.Name, "Hello")
	fmt.Println("Inspection", err)

	// TODO: Call back
	// - Call Hello
	//

	return &agent.RegisterResponse{
		Msg: fmt.Sprintf("%s - %s:%d", in.Name, in.Address, in.Port),
	}, nil
}

var r *reflectionHandler

func main() {
	fmt.Println("Start server")

	go func() {
		r = &reflectionHandler{}
	}()

	s := grpc.NewServer()
	agent.RegisterRegistrationServiceServer(s, &registrationServer{})
	reflection.Register(s)

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		panic(err)
	}

	if err := s.Serve(l); err != nil {
		panic(err)
	}
}
