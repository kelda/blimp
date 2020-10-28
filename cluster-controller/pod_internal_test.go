package main

import (
	"testing"

	"github.com/golang/protobuf/proto"
	composeTypes "github.com/kelda/compose-go/types"

	"github.com/kelda/blimp/pkg/proto/wait"
	"github.com/kelda/blimp/pkg/hash"
)

func TestWaitSpecHash(t *testing.T) {
	spec := wait.WaitSpec{
		DependsOn: marshalDependencies(
			composeTypes.DependsOnConfig{},
			[]string{"foo", "bar", "baz", "quux", "quuz"},
		)}

	getHash := func() string {
		waitSpecBytes, err := proto.Marshal(&spec)
		if err != nil {
			panic(err)
		}
		return hash.Bytes(waitSpecBytes)
	}

	lastHash := getHash()
	for i := 0; i < 100; i++ {
		if h := getHash(); h != lastHash {
			t.Errorf("got different hashes: %s and %s", h, lastHash)
		}
	}
}
