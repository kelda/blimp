package main

import (
	"github.com/kelda-inc/blimp/cluster-controller/httpapi"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

type watchStatusShim struct {
	httpapi.WebSocketStream
}

func (shim watchStatusShim) Send(msg *cluster.GetStatusResponse) error {
	return shim.SendProtoMessage(msg)
}

type blimpUpPreviewShim struct {
	httpapi.WebSocketStream
}

func (shim blimpUpPreviewShim) Send(msg *cluster.BlimpUpPreviewResponse) error {
	return shim.SendProtoMessage(msg)
}
