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
		SubTreeArgs{}, SubTreeReply{},
		CoSiTrees{}, CoSiReplyTrees{},
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
	Message   []byte
}

// CoSiTrees contains multiple trees
type CoSiTrees struct {
	Trees   []*onet.Tree
	Message []byte
}

// CoSiReplyTrees returns the signatures and the original message
type CoSiReplyTrees struct {
	Signatures [][]byte
	Message    []byte
}

// SubTreeArgs contains the arguments for the function GenerateSubTrees
type SubTreeArgs struct {
	Roster       *onet.Roster
	BF           int
	SubTreeCount int
}

// SubTreeReply contains the list of subtrees
type SubTreeReply struct {
	Trees []*onet.Tree
}
