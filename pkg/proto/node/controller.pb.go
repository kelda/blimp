// Code generated by protoc-gen-go. DO NOT EDIT.
// source: blimp/node/v0/controller.proto

package node

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	errors "github.com/kelda/blimp/pkg/proto/errors"
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

// In a Tunnel, name, port, and token are used. In an ExposedTunnel, namespace is used.
type TunnelHeader struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Port                 uint32   `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Token                string   `protobuf:"bytes,3,opt,name=token,proto3" json:"token,omitempty"`
	Namespace            string   `protobuf:"bytes,4,opt,name=namespace,proto3" json:"namespace,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TunnelHeader) Reset()         { *m = TunnelHeader{} }
func (m *TunnelHeader) String() string { return proto.CompactTextString(m) }
func (*TunnelHeader) ProtoMessage()    {}
func (*TunnelHeader) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe3c8ce6343e9a1, []int{0}
}

func (m *TunnelHeader) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TunnelHeader.Unmarshal(m, b)
}
func (m *TunnelHeader) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TunnelHeader.Marshal(b, m, deterministic)
}
func (m *TunnelHeader) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TunnelHeader.Merge(m, src)
}
func (m *TunnelHeader) XXX_Size() int {
	return xxx_messageInfo_TunnelHeader.Size(m)
}
func (m *TunnelHeader) XXX_DiscardUnknown() {
	xxx_messageInfo_TunnelHeader.DiscardUnknown(m)
}

var xxx_messageInfo_TunnelHeader proto.InternalMessageInfo

func (m *TunnelHeader) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *TunnelHeader) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *TunnelHeader) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *TunnelHeader) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

type EOF struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EOF) Reset()         { *m = EOF{} }
func (m *EOF) String() string { return proto.CompactTextString(m) }
func (*EOF) ProtoMessage()    {}
func (*EOF) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe3c8ce6343e9a1, []int{1}
}

func (m *EOF) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EOF.Unmarshal(m, b)
}
func (m *EOF) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EOF.Marshal(b, m, deterministic)
}
func (m *EOF) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EOF.Merge(m, src)
}
func (m *EOF) XXX_Size() int {
	return xxx_messageInfo_EOF.Size(m)
}
func (m *EOF) XXX_DiscardUnknown() {
	xxx_messageInfo_EOF.DiscardUnknown(m)
}

var xxx_messageInfo_EOF proto.InternalMessageInfo

// The first message the Client sends to the server must be a header.  After
// that all messages either direction must be bufs.  Optionally, either
// direction may send an EOF to indicate they have no more to send.
type TunnelMsg struct {
	// Types that are valid to be assigned to Msg:
	//	*TunnelMsg_Error
	//	*TunnelMsg_Header
	//	*TunnelMsg_Buf
	//	*TunnelMsg_Eof
	Msg                  isTunnelMsg_Msg `protobuf_oneof:"msg"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *TunnelMsg) Reset()         { *m = TunnelMsg{} }
func (m *TunnelMsg) String() string { return proto.CompactTextString(m) }
func (*TunnelMsg) ProtoMessage()    {}
func (*TunnelMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe3c8ce6343e9a1, []int{2}
}

func (m *TunnelMsg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TunnelMsg.Unmarshal(m, b)
}
func (m *TunnelMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TunnelMsg.Marshal(b, m, deterministic)
}
func (m *TunnelMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TunnelMsg.Merge(m, src)
}
func (m *TunnelMsg) XXX_Size() int {
	return xxx_messageInfo_TunnelMsg.Size(m)
}
func (m *TunnelMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_TunnelMsg.DiscardUnknown(m)
}

var xxx_messageInfo_TunnelMsg proto.InternalMessageInfo

type isTunnelMsg_Msg interface {
	isTunnelMsg_Msg()
}

type TunnelMsg_Error struct {
	Error *errors.Error `protobuf:"bytes,1,opt,name=error,proto3,oneof"`
}

type TunnelMsg_Header struct {
	Header *TunnelHeader `protobuf:"bytes,2,opt,name=header,proto3,oneof"`
}

type TunnelMsg_Buf struct {
	Buf []byte `protobuf:"bytes,3,opt,name=buf,proto3,oneof"`
}

type TunnelMsg_Eof struct {
	Eof *EOF `protobuf:"bytes,4,opt,name=eof,proto3,oneof"`
}

func (*TunnelMsg_Error) isTunnelMsg_Msg() {}

func (*TunnelMsg_Header) isTunnelMsg_Msg() {}

func (*TunnelMsg_Buf) isTunnelMsg_Msg() {}

func (*TunnelMsg_Eof) isTunnelMsg_Msg() {}

func (m *TunnelMsg) GetMsg() isTunnelMsg_Msg {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *TunnelMsg) GetError() *errors.Error {
	if x, ok := m.GetMsg().(*TunnelMsg_Error); ok {
		return x.Error
	}
	return nil
}

func (m *TunnelMsg) GetHeader() *TunnelHeader {
	if x, ok := m.GetMsg().(*TunnelMsg_Header); ok {
		return x.Header
	}
	return nil
}

func (m *TunnelMsg) GetBuf() []byte {
	if x, ok := m.GetMsg().(*TunnelMsg_Buf); ok {
		return x.Buf
	}
	return nil
}

func (m *TunnelMsg) GetEof() *EOF {
	if x, ok := m.GetMsg().(*TunnelMsg_Eof); ok {
		return x.Eof
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*TunnelMsg) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*TunnelMsg_Error)(nil),
		(*TunnelMsg_Header)(nil),
		(*TunnelMsg_Buf)(nil),
		(*TunnelMsg_Eof)(nil),
	}
}

type SyncStatusResponse struct {
	// Types that are valid to be assigned to Msg:
	//	*SyncStatusResponse_Token
	//	*SyncStatusResponse_Synced
	Msg                  isSyncStatusResponse_Msg `protobuf_oneof:"msg"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *SyncStatusResponse) Reset()         { *m = SyncStatusResponse{} }
func (m *SyncStatusResponse) String() string { return proto.CompactTextString(m) }
func (*SyncStatusResponse) ProtoMessage()    {}
func (*SyncStatusResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe3c8ce6343e9a1, []int{3}
}

func (m *SyncStatusResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SyncStatusResponse.Unmarshal(m, b)
}
func (m *SyncStatusResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SyncStatusResponse.Marshal(b, m, deterministic)
}
func (m *SyncStatusResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SyncStatusResponse.Merge(m, src)
}
func (m *SyncStatusResponse) XXX_Size() int {
	return xxx_messageInfo_SyncStatusResponse.Size(m)
}
func (m *SyncStatusResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SyncStatusResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SyncStatusResponse proto.InternalMessageInfo

type isSyncStatusResponse_Msg interface {
	isSyncStatusResponse_Msg()
}

type SyncStatusResponse_Token struct {
	Token string `protobuf:"bytes,1,opt,name=token,proto3,oneof"`
}

type SyncStatusResponse_Synced struct {
	Synced bool `protobuf:"varint,2,opt,name=synced,proto3,oneof"`
}

func (*SyncStatusResponse_Token) isSyncStatusResponse_Msg() {}

func (*SyncStatusResponse_Synced) isSyncStatusResponse_Msg() {}

func (m *SyncStatusResponse) GetMsg() isSyncStatusResponse_Msg {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *SyncStatusResponse) GetToken() string {
	if x, ok := m.GetMsg().(*SyncStatusResponse_Token); ok {
		return x.Token
	}
	return ""
}

func (m *SyncStatusResponse) GetSynced() bool {
	if x, ok := m.GetMsg().(*SyncStatusResponse_Synced); ok {
		return x.Synced
	}
	return false
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*SyncStatusResponse) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*SyncStatusResponse_Token)(nil),
		(*SyncStatusResponse_Synced)(nil),
	}
}

type GetSyncStatusRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetSyncStatusRequest) Reset()         { *m = GetSyncStatusRequest{} }
func (m *GetSyncStatusRequest) String() string { return proto.CompactTextString(m) }
func (*GetSyncStatusRequest) ProtoMessage()    {}
func (*GetSyncStatusRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffe3c8ce6343e9a1, []int{4}
}

func (m *GetSyncStatusRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetSyncStatusRequest.Unmarshal(m, b)
}
func (m *GetSyncStatusRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetSyncStatusRequest.Marshal(b, m, deterministic)
}
func (m *GetSyncStatusRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetSyncStatusRequest.Merge(m, src)
}
func (m *GetSyncStatusRequest) XXX_Size() int {
	return xxx_messageInfo_GetSyncStatusRequest.Size(m)
}
func (m *GetSyncStatusRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetSyncStatusRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetSyncStatusRequest proto.InternalMessageInfo

func init() {
	proto.RegisterType((*TunnelHeader)(nil), "blimp.node.v0.TunnelHeader")
	proto.RegisterType((*EOF)(nil), "blimp.node.v0.EOF")
	proto.RegisterType((*TunnelMsg)(nil), "blimp.node.v0.TunnelMsg")
	proto.RegisterType((*SyncStatusResponse)(nil), "blimp.node.v0.SyncStatusResponse")
	proto.RegisterType((*GetSyncStatusRequest)(nil), "blimp.node.v0.GetSyncStatusRequest")
}

func init() {
	proto.RegisterFile("blimp/node/v0/controller.proto", fileDescriptor_ffe3c8ce6343e9a1)
}

var fileDescriptor_ffe3c8ce6343e9a1 = []byte{
	// 421 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x92, 0x51, 0x6f, 0xd3, 0x40,
	0x0c, 0xc7, 0x1b, 0xb2, 0x56, 0xd4, 0x5d, 0x1f, 0xb0, 0xa6, 0x2a, 0x2a, 0x13, 0x1a, 0x41, 0x40,
	0x9f, 0x2e, 0x55, 0x11, 0x5f, 0xa0, 0xa8, 0xa3, 0x3c, 0x94, 0x49, 0x19, 0x4f, 0xbc, 0xa5, 0x89,
	0x9b, 0x85, 0xa6, 0x77, 0xe1, 0xee, 0x52, 0xb1, 0x0f, 0xc6, 0xd7, 0x43, 0xe8, 0x7c, 0x1b, 0x8c,
	0x52, 0x9e, 0x78, 0xb3, 0xcf, 0x7f, 0xdb, 0x3f, 0xfb, 0x0c, 0xcf, 0xd6, 0x75, 0xb5, 0x6b, 0x12,
	0xa9, 0x0a, 0x4a, 0xf6, 0xd3, 0x24, 0x57, 0xd2, 0x6a, 0x55, 0xd7, 0xa4, 0x45, 0xa3, 0x95, 0x55,
	0x38, 0xe4, 0xb8, 0x70, 0x71, 0xb1, 0x9f, 0x8e, 0xcf, 0xbd, 0x9c, 0xb4, 0x56, 0xda, 0xb8, 0x04,
	0x6f, 0x79, 0x71, 0xfc, 0x05, 0x4e, 0x3f, 0xb5, 0x52, 0x52, 0xbd, 0xa4, 0xac, 0x20, 0x8d, 0x08,
	0x27, 0x32, 0xdb, 0x51, 0x14, 0x5c, 0x04, 0x93, 0x7e, 0xca, 0xb6, 0x7b, 0x6b, 0x94, 0xb6, 0xd1,
	0xa3, 0x8b, 0x60, 0x32, 0x4c, 0xd9, 0xc6, 0x33, 0xe8, 0x5a, 0xb5, 0x25, 0x19, 0x85, 0x2c, 0xf4,
	0x0e, 0x9e, 0x43, 0xdf, 0x65, 0x98, 0x26, 0xcb, 0x29, 0x3a, 0xe1, 0xc8, 0xef, 0x87, 0xb8, 0x0b,
	0xe1, 0xe2, 0xea, 0x32, 0xfe, 0x1e, 0x40, 0xdf, 0xf7, 0x5c, 0x99, 0x12, 0x05, 0x74, 0x19, 0x88,
	0x3b, 0x0e, 0x66, 0x23, 0xe1, 0xe9, 0xef, 0x20, 0xf7, 0x53, 0xb1, 0x70, 0xd6, 0xb2, 0x93, 0x7a,
	0x19, 0xbe, 0x85, 0xde, 0x0d, 0xa3, 0x32, 0xce, 0x60, 0xf6, 0x54, 0xfc, 0x31, 0xae, 0x78, 0x38,
	0xcd, 0xb2, 0x93, 0xde, 0x89, 0x11, 0x21, 0x5c, 0xb7, 0x1b, 0xa6, 0x3d, 0x5d, 0x76, 0x52, 0xe7,
	0xe0, 0x2b, 0x08, 0x49, 0x6d, 0x98, 0x73, 0x30, 0xc3, 0x83, 0x3a, 0x8b, 0xab, 0x4b, 0xa7, 0x23,
	0xb5, 0x99, 0x77, 0x21, 0xdc, 0x99, 0x32, 0x5e, 0x01, 0x5e, 0xdf, 0xca, 0xfc, 0xda, 0x66, 0xb6,
	0x35, 0x29, 0x99, 0x46, 0x49, 0x43, 0x38, 0xba, 0x5f, 0x04, 0x6f, 0xcc, 0x71, 0xfa, 0x55, 0x44,
	0xd0, 0x33, 0xb7, 0x32, 0xa7, 0x82, 0x39, 0x1f, 0x3b, 0x14, 0xef, 0xdf, 0x97, 0x1b, 0xc1, 0xd9,
	0x7b, 0xb2, 0x0f, 0x2b, 0x7e, 0x6d, 0xc9, 0xd8, 0xd9, 0x8f, 0x00, 0xe0, 0xdd, 0xaf, 0x3f, 0xc5,
	0x39, 0xf4, 0xfc, 0x48, 0x18, 0x1d, 0x9d, 0x74, 0x65, 0xca, 0xf1, 0x3f, 0x23, 0x71, 0x67, 0x12,
	0x4c, 0x03, 0xfc, 0x00, 0xc3, 0xc5, 0xb7, 0x46, 0x19, 0x2a, 0xfe, 0xbb, 0x54, 0x06, 0x4f, 0x1c,
	0xf2, 0x47, 0x65, 0xab, 0x4d, 0x95, 0x67, 0xb6, 0x52, 0xd2, 0xe0, 0xf3, 0x83, 0xa4, 0xbf, 0xd7,
	0x34, 0x7e, 0x71, 0x20, 0x39, 0x36, 0xba, 0x6f, 0x31, 0x7f, 0xfd, 0xf9, 0x65, 0x59, 0xd9, 0x9b,
	0x76, 0x2d, 0x72, 0xb5, 0x4b, 0xb6, 0x54, 0x17, 0x59, 0xe2, 0x6f, 0xb8, 0xd9, 0x96, 0x09, 0x9f,
	0x2d, 0x1f, 0xff, 0xba, 0xc7, 0xf6, 0x9b, 0x9f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x44, 0x7d, 0xac,
	0x28, 0x11, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ControllerClient is the client API for Controller service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ControllerClient interface {
	Tunnel(ctx context.Context, opts ...grpc.CallOption) (Controller_TunnelClient, error)
	ExposedTunnel(ctx context.Context, opts ...grpc.CallOption) (Controller_ExposedTunnelClient, error)
	// The request and responses are flipped because the node controller is
	// querying the CLI for status updates, but the CLI is initiating the
	// connection.
	SyncNotifications(ctx context.Context, opts ...grpc.CallOption) (Controller_SyncNotificationsClient, error)
}

type controllerClient struct {
	cc grpc.ClientConnInterface
}

func NewControllerClient(cc grpc.ClientConnInterface) ControllerClient {
	return &controllerClient{cc}
}

func (c *controllerClient) Tunnel(ctx context.Context, opts ...grpc.CallOption) (Controller_TunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Controller_serviceDesc.Streams[0], "/blimp.node.v0.Controller/Tunnel", opts...)
	if err != nil {
		return nil, err
	}
	x := &controllerTunnelClient{stream}
	return x, nil
}

type Controller_TunnelClient interface {
	Send(*TunnelMsg) error
	Recv() (*TunnelMsg, error)
	grpc.ClientStream
}

type controllerTunnelClient struct {
	grpc.ClientStream
}

func (x *controllerTunnelClient) Send(m *TunnelMsg) error {
	return x.ClientStream.SendMsg(m)
}

func (x *controllerTunnelClient) Recv() (*TunnelMsg, error) {
	m := new(TunnelMsg)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *controllerClient) ExposedTunnel(ctx context.Context, opts ...grpc.CallOption) (Controller_ExposedTunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Controller_serviceDesc.Streams[1], "/blimp.node.v0.Controller/ExposedTunnel", opts...)
	if err != nil {
		return nil, err
	}
	x := &controllerExposedTunnelClient{stream}
	return x, nil
}

type Controller_ExposedTunnelClient interface {
	Send(*TunnelMsg) error
	Recv() (*TunnelMsg, error)
	grpc.ClientStream
}

type controllerExposedTunnelClient struct {
	grpc.ClientStream
}

func (x *controllerExposedTunnelClient) Send(m *TunnelMsg) error {
	return x.ClientStream.SendMsg(m)
}

func (x *controllerExposedTunnelClient) Recv() (*TunnelMsg, error) {
	m := new(TunnelMsg)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *controllerClient) SyncNotifications(ctx context.Context, opts ...grpc.CallOption) (Controller_SyncNotificationsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Controller_serviceDesc.Streams[2], "/blimp.node.v0.Controller/SyncNotifications", opts...)
	if err != nil {
		return nil, err
	}
	x := &controllerSyncNotificationsClient{stream}
	return x, nil
}

type Controller_SyncNotificationsClient interface {
	Send(*SyncStatusResponse) error
	Recv() (*GetSyncStatusRequest, error)
	grpc.ClientStream
}

type controllerSyncNotificationsClient struct {
	grpc.ClientStream
}

func (x *controllerSyncNotificationsClient) Send(m *SyncStatusResponse) error {
	return x.ClientStream.SendMsg(m)
}

func (x *controllerSyncNotificationsClient) Recv() (*GetSyncStatusRequest, error) {
	m := new(GetSyncStatusRequest)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ControllerServer is the server API for Controller service.
type ControllerServer interface {
	Tunnel(Controller_TunnelServer) error
	ExposedTunnel(Controller_ExposedTunnelServer) error
	// The request and responses are flipped because the node controller is
	// querying the CLI for status updates, but the CLI is initiating the
	// connection.
	SyncNotifications(Controller_SyncNotificationsServer) error
}

// UnimplementedControllerServer can be embedded to have forward compatible implementations.
type UnimplementedControllerServer struct {
}

func (*UnimplementedControllerServer) Tunnel(srv Controller_TunnelServer) error {
	return status.Errorf(codes.Unimplemented, "method Tunnel not implemented")
}
func (*UnimplementedControllerServer) ExposedTunnel(srv Controller_ExposedTunnelServer) error {
	return status.Errorf(codes.Unimplemented, "method ExposedTunnel not implemented")
}
func (*UnimplementedControllerServer) SyncNotifications(srv Controller_SyncNotificationsServer) error {
	return status.Errorf(codes.Unimplemented, "method SyncNotifications not implemented")
}

func RegisterControllerServer(s *grpc.Server, srv ControllerServer) {
	s.RegisterService(&_Controller_serviceDesc, srv)
}

func _Controller_Tunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ControllerServer).Tunnel(&controllerTunnelServer{stream})
}

type Controller_TunnelServer interface {
	Send(*TunnelMsg) error
	Recv() (*TunnelMsg, error)
	grpc.ServerStream
}

type controllerTunnelServer struct {
	grpc.ServerStream
}

func (x *controllerTunnelServer) Send(m *TunnelMsg) error {
	return x.ServerStream.SendMsg(m)
}

func (x *controllerTunnelServer) Recv() (*TunnelMsg, error) {
	m := new(TunnelMsg)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Controller_ExposedTunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ControllerServer).ExposedTunnel(&controllerExposedTunnelServer{stream})
}

type Controller_ExposedTunnelServer interface {
	Send(*TunnelMsg) error
	Recv() (*TunnelMsg, error)
	grpc.ServerStream
}

type controllerExposedTunnelServer struct {
	grpc.ServerStream
}

func (x *controllerExposedTunnelServer) Send(m *TunnelMsg) error {
	return x.ServerStream.SendMsg(m)
}

func (x *controllerExposedTunnelServer) Recv() (*TunnelMsg, error) {
	m := new(TunnelMsg)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Controller_SyncNotifications_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ControllerServer).SyncNotifications(&controllerSyncNotificationsServer{stream})
}

type Controller_SyncNotificationsServer interface {
	Send(*GetSyncStatusRequest) error
	Recv() (*SyncStatusResponse, error)
	grpc.ServerStream
}

type controllerSyncNotificationsServer struct {
	grpc.ServerStream
}

func (x *controllerSyncNotificationsServer) Send(m *GetSyncStatusRequest) error {
	return x.ServerStream.SendMsg(m)
}

func (x *controllerSyncNotificationsServer) Recv() (*SyncStatusResponse, error) {
	m := new(SyncStatusResponse)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _Controller_serviceDesc = grpc.ServiceDesc{
	ServiceName: "blimp.node.v0.Controller",
	HandlerType: (*ControllerServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Tunnel",
			Handler:       _Controller_Tunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "ExposedTunnel",
			Handler:       _Controller_ExposedTunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "SyncNotifications",
			Handler:       _Controller_SyncNotifications_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "blimp/node/v0/controller.proto",
}
