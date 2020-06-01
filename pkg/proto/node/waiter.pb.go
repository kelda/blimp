// Code generated by protoc-gen-go. DO NOT EDIT.
// source: blimp/node/v0/waiter.proto

package node

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	errors "github.com/kelda-inc/blimp/pkg/proto/errors"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type CheckReadyRequest struct {
	Namespace            string    `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	WaitSpec             *WaitSpec `protobuf:"bytes,2,opt,name=wait_spec,json=waitSpec,proto3" json:"wait_spec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *CheckReadyRequest) Reset()         { *m = CheckReadyRequest{} }
func (m *CheckReadyRequest) String() string { return proto.CompactTextString(m) }
func (*CheckReadyRequest) ProtoMessage()    {}
func (*CheckReadyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e4d99ca2fb60d17, []int{0}
}

func (m *CheckReadyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckReadyRequest.Unmarshal(m, b)
}
func (m *CheckReadyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckReadyRequest.Marshal(b, m, deterministic)
}
func (m *CheckReadyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckReadyRequest.Merge(m, src)
}
func (m *CheckReadyRequest) XXX_Size() int {
	return xxx_messageInfo_CheckReadyRequest.Size(m)
}
func (m *CheckReadyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckReadyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CheckReadyRequest proto.InternalMessageInfo

func (m *CheckReadyRequest) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *CheckReadyRequest) GetWaitSpec() *WaitSpec {
	if m != nil {
		return m.WaitSpec
	}
	return nil
}

type WaitSpec struct {
	// depends_on is a list of services that must be running or healthy
	// before the service can start.
	DependsOn map[string]*ServiceCondition `protobuf:"bytes,1,rep,name=depends_on,json=dependsOn,proto3" json:"depends_on,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// bind_volumes is a list of paths that must be fully synced before the
	// service can start.
	BindVolumes []string `protobuf:"bytes,2,rep,name=bind_volumes,json=bindVolumes,proto3" json:"bind_volumes,omitempty"`
	// finished_volume_init is a list of services that must have finished initializing
	// volumes before the service can start.
	FinishedVolumeInit   []string `protobuf:"bytes,3,rep,name=finished_volume_init,json=finishedVolumeInit,proto3" json:"finished_volume_init,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WaitSpec) Reset()         { *m = WaitSpec{} }
func (m *WaitSpec) String() string { return proto.CompactTextString(m) }
func (*WaitSpec) ProtoMessage()    {}
func (*WaitSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e4d99ca2fb60d17, []int{1}
}

func (m *WaitSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WaitSpec.Unmarshal(m, b)
}
func (m *WaitSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WaitSpec.Marshal(b, m, deterministic)
}
func (m *WaitSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WaitSpec.Merge(m, src)
}
func (m *WaitSpec) XXX_Size() int {
	return xxx_messageInfo_WaitSpec.Size(m)
}
func (m *WaitSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_WaitSpec.DiscardUnknown(m)
}

var xxx_messageInfo_WaitSpec proto.InternalMessageInfo

func (m *WaitSpec) GetDependsOn() map[string]*ServiceCondition {
	if m != nil {
		return m.DependsOn
	}
	return nil
}

func (m *WaitSpec) GetBindVolumes() []string {
	if m != nil {
		return m.BindVolumes
	}
	return nil
}

func (m *WaitSpec) GetFinishedVolumeInit() []string {
	if m != nil {
		return m.FinishedVolumeInit
	}
	return nil
}

type ServiceCondition struct {
	Condition            string   `protobuf:"bytes,1,opt,name=Condition,proto3" json:"Condition,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServiceCondition) Reset()         { *m = ServiceCondition{} }
func (m *ServiceCondition) String() string { return proto.CompactTextString(m) }
func (*ServiceCondition) ProtoMessage()    {}
func (*ServiceCondition) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e4d99ca2fb60d17, []int{2}
}

func (m *ServiceCondition) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceCondition.Unmarshal(m, b)
}
func (m *ServiceCondition) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceCondition.Marshal(b, m, deterministic)
}
func (m *ServiceCondition) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceCondition.Merge(m, src)
}
func (m *ServiceCondition) XXX_Size() int {
	return xxx_messageInfo_ServiceCondition.Size(m)
}
func (m *ServiceCondition) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceCondition.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceCondition proto.InternalMessageInfo

func (m *ServiceCondition) GetCondition() string {
	if m != nil {
		return m.Condition
	}
	return ""
}

type CheckReadyResponse struct {
	Error *errors.Error `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Ready bool          `protobuf:"varint,2,opt,name=ready,proto3" json:"ready,omitempty"`
	// An optional message providing more information on why the container
	// needs to wait.
	Reason               string   `protobuf:"bytes,3,opt,name=reason,proto3" json:"reason,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CheckReadyResponse) Reset()         { *m = CheckReadyResponse{} }
func (m *CheckReadyResponse) String() string { return proto.CompactTextString(m) }
func (*CheckReadyResponse) ProtoMessage()    {}
func (*CheckReadyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e4d99ca2fb60d17, []int{3}
}

func (m *CheckReadyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CheckReadyResponse.Unmarshal(m, b)
}
func (m *CheckReadyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CheckReadyResponse.Marshal(b, m, deterministic)
}
func (m *CheckReadyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CheckReadyResponse.Merge(m, src)
}
func (m *CheckReadyResponse) XXX_Size() int {
	return xxx_messageInfo_CheckReadyResponse.Size(m)
}
func (m *CheckReadyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CheckReadyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CheckReadyResponse proto.InternalMessageInfo

func (m *CheckReadyResponse) GetError() *errors.Error {
	if m != nil {
		return m.Error
	}
	return nil
}

func (m *CheckReadyResponse) GetReady() bool {
	if m != nil {
		return m.Ready
	}
	return false
}

func (m *CheckReadyResponse) GetReason() string {
	if m != nil {
		return m.Reason
	}
	return ""
}

func init() {
	proto.RegisterType((*CheckReadyRequest)(nil), "blimp.node.v0.CheckReadyRequest")
	proto.RegisterType((*WaitSpec)(nil), "blimp.node.v0.WaitSpec")
	proto.RegisterMapType((map[string]*ServiceCondition)(nil), "blimp.node.v0.WaitSpec.DependsOnEntry")
	proto.RegisterType((*ServiceCondition)(nil), "blimp.node.v0.ServiceCondition")
	proto.RegisterType((*CheckReadyResponse)(nil), "blimp.node.v0.CheckReadyResponse")
}

func init() {
	proto.RegisterFile("blimp/node/v0/waiter.proto", fileDescriptor_3e4d99ca2fb60d17)
}

var fileDescriptor_3e4d99ca2fb60d17 = []byte{
	// 437 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xdf, 0x8b, 0xd3, 0x40,
	0x10, 0xc7, 0x4d, 0x43, 0x8f, 0x66, 0xaa, 0x72, 0x2e, 0xc7, 0x19, 0xca, 0x81, 0xb9, 0x3c, 0x48,
	0x45, 0x4d, 0x42, 0x55, 0x10, 0x1f, 0xef, 0xec, 0x83, 0x4f, 0xc2, 0x1e, 0x7a, 0x20, 0x48, 0x49,
	0x93, 0xb1, 0x5d, 0xda, 0xee, 0xae, 0xbb, 0x9b, 0x1c, 0xfd, 0x03, 0xfc, 0xbf, 0x65, 0x77, 0x93,
	0x3b, 0xaf, 0xa2, 0x6f, 0xf3, 0xe3, 0x93, 0x7c, 0x67, 0x67, 0xbe, 0x30, 0x59, 0x6e, 0xd9, 0x4e,
	0xe6, 0x5c, 0xd4, 0x98, 0xb7, 0x45, 0x7e, 0x53, 0x32, 0x83, 0x2a, 0x93, 0x4a, 0x18, 0x41, 0x1e,
	0xb9, 0x5e, 0x66, 0x7b, 0x59, 0x5b, 0x4c, 0xce, 0x3c, 0x8a, 0x4a, 0x09, 0xa5, 0x2d, 0xec, 0x23,
	0x0f, 0xa7, 0x2b, 0x78, 0x72, 0xb9, 0xc6, 0x6a, 0x43, 0xb1, 0xac, 0xf7, 0x14, 0x7f, 0x36, 0xa8,
	0x0d, 0x39, 0x83, 0x88, 0x97, 0x3b, 0xd4, 0xb2, 0xac, 0x30, 0x0e, 0x92, 0x60, 0x1a, 0xd1, 0xbb,
	0x02, 0x79, 0x0b, 0x91, 0xd5, 0x5b, 0x68, 0x89, 0x55, 0x3c, 0x48, 0x82, 0xe9, 0x78, 0xf6, 0x34,
	0xbb, 0xa7, 0x99, 0x5d, 0x97, 0xcc, 0x5c, 0x49, 0xac, 0xe8, 0xe8, 0xa6, 0x8b, 0xd2, 0x5f, 0x03,
	0x18, 0xf5, 0x65, 0x32, 0x07, 0xa8, 0x51, 0x22, 0xaf, 0xf5, 0x42, 0xf0, 0x38, 0x48, 0xc2, 0xe9,
	0x78, 0xf6, 0xfc, 0x1f, 0xff, 0xc8, 0x3e, 0x7a, 0xf2, 0x33, 0x9f, 0x73, 0xa3, 0xf6, 0x34, 0xaa,
	0xfb, 0x9c, 0x9c, 0xc3, 0xc3, 0x25, 0xe3, 0xf5, 0xa2, 0x15, 0xdb, 0x66, 0x87, 0x3a, 0x1e, 0x24,
	0xe1, 0x34, 0xa2, 0x63, 0x5b, 0xfb, 0xea, 0x4b, 0xa4, 0x80, 0x93, 0x1f, 0x8c, 0x33, 0xbd, 0xc6,
	0x1e, 0x5b, 0x30, 0xce, 0x4c, 0x1c, 0x3a, 0x94, 0xf4, 0x3d, 0x8f, 0x7f, 0xe2, 0xcc, 0x4c, 0xbe,
	0xc3, 0xe3, 0xfb, 0x8a, 0xe4, 0x18, 0xc2, 0x0d, 0xee, 0xbb, 0x45, 0xd8, 0x90, 0xbc, 0x83, 0x61,
	0x5b, 0x6e, 0x1b, 0xec, 0x9e, 0xff, 0xec, 0x60, 0xf4, 0x2b, 0x54, 0x2d, 0xab, 0xf0, 0x52, 0xf0,
	0x9a, 0x19, 0x26, 0x38, 0xf5, 0xf4, 0x87, 0xc1, 0xfb, 0x20, 0x2d, 0xe0, 0xf8, 0xb0, 0x6d, 0xf7,
	0x7d, 0x9b, 0xf4, 0xfb, 0xbe, 0x2d, 0xa4, 0x12, 0xc8, 0x9f, 0x27, 0xd2, 0x52, 0x70, 0x8d, 0xe4,
	0x15, 0x0c, 0xdd, 0x21, 0x1d, 0x3f, 0x9e, 0x9d, 0x76, 0x23, 0x74, 0xc7, 0x6d, 0x8b, 0x6c, 0x6e,
	0x23, 0xea, 0x21, 0x72, 0x02, 0x43, 0x65, 0x3f, 0x77, 0x03, 0x8f, 0xa8, 0x4f, 0xc8, 0x29, 0x1c,
	0x29, 0x2c, 0xb5, 0xe0, 0x71, 0xe8, 0x44, 0xbb, 0x6c, 0x56, 0x01, 0x5c, 0x08, 0x61, 0xae, 0x9d,
	0xab, 0xc8, 0x17, 0x80, 0x3b, 0x7d, 0x92, 0x1c, 0xbc, 0xf5, 0x2f, 0xf7, 0x4c, 0xce, 0xff, 0x43,
	0xf8, 0xe1, 0xd3, 0x07, 0x45, 0x70, 0xf1, 0xf2, 0xdb, 0x8b, 0x15, 0x33, 0xeb, 0x66, 0x99, 0x55,
	0x62, 0x97, 0x6f, 0x70, 0x5b, 0x97, 0xaf, 0x19, 0xaf, 0x72, 0x6f, 0x57, 0xb9, 0x59, 0xe5, 0xce,
	0xa1, 0xce, 0xe3, 0xcb, 0x23, 0x17, 0xbf, 0xf9, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x56, 0x4c, 0x3b,
	0x9c, 0xf8, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// BootWaiterClient is the client API for BootWaiter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BootWaiterClient interface {
	CheckReady(ctx context.Context, in *CheckReadyRequest, opts ...grpc.CallOption) (BootWaiter_CheckReadyClient, error)
}

type bootWaiterClient struct {
	cc grpc.ClientConnInterface
}

func NewBootWaiterClient(cc grpc.ClientConnInterface) BootWaiterClient {
	return &bootWaiterClient{cc}
}

func (c *bootWaiterClient) CheckReady(ctx context.Context, in *CheckReadyRequest, opts ...grpc.CallOption) (BootWaiter_CheckReadyClient, error) {
	stream, err := c.cc.NewStream(ctx, &_BootWaiter_serviceDesc.Streams[0], "/blimp.node.v0.BootWaiter/CheckReady", opts...)
	if err != nil {
		return nil, err
	}
	x := &bootWaiterCheckReadyClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type BootWaiter_CheckReadyClient interface {
	Recv() (*CheckReadyResponse, error)
	grpc.ClientStream
}

type bootWaiterCheckReadyClient struct {
	grpc.ClientStream
}

func (x *bootWaiterCheckReadyClient) Recv() (*CheckReadyResponse, error) {
	m := new(CheckReadyResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// BootWaiterServer is the server API for BootWaiter service.
type BootWaiterServer interface {
	CheckReady(*CheckReadyRequest, BootWaiter_CheckReadyServer) error
}

// UnimplementedBootWaiterServer can be embedded to have forward compatible implementations.
type UnimplementedBootWaiterServer struct {
}

func (*UnimplementedBootWaiterServer) CheckReady(req *CheckReadyRequest, srv BootWaiter_CheckReadyServer) error {
	return status.Errorf(codes.Unimplemented, "method CheckReady not implemented")
}

func RegisterBootWaiterServer(s *grpc.Server, srv BootWaiterServer) {
	s.RegisterService(&_BootWaiter_serviceDesc, srv)
}

func _BootWaiter_CheckReady_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(CheckReadyRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(BootWaiterServer).CheckReady(m, &bootWaiterCheckReadyServer{stream})
}

type BootWaiter_CheckReadyServer interface {
	Send(*CheckReadyResponse) error
	grpc.ServerStream
}

type bootWaiterCheckReadyServer struct {
	grpc.ServerStream
}

func (x *bootWaiterCheckReadyServer) Send(m *CheckReadyResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _BootWaiter_serviceDesc = grpc.ServiceDesc{
	ServiceName: "blimp.node.v0.BootWaiter",
	HandlerType: (*BootWaiterServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "CheckReady",
			Handler:       _BootWaiter_CheckReady_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "blimp/node/v0/waiter.proto",
}
