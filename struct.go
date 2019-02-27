package nylechain

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(
		CoSi{}, CoSiReply{},
	)
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// CoSi will run the cosi protocol on the roster
type CoSi struct {
	Roster  *onet.Roster
	Message []byte
}

// CoSiReply returns the signature and the original message
type CoSiReply struct {
	Signature []byte
	Message []byte
}
