package service

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(
		SubTreeArgs{}, SubTreeReply{},
		CoSiTrees{}, CoSiReplyTrees{},
		TxStorage{}, PropagateData{},
		GenesisArgs{}, SetupArgs{},
		VoidReply{}, MemoryRequest{},
		MemoryReply{},
	)
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// VoidReply is used when there's nothing to reply
type VoidReply struct{}

// SetupArgs contains the arguments for service method Setup
type SetupArgs struct {
	Roster       *onet.Roster
	Translations map[onet.TreeID][]byte
	Distances    map[string]map[string]float64
}

// PropagateData is what is received by propagateHandler. It's propagated by TreesBLSCoSi.
type PropagateData struct {
	ServerID  string
	Tx        transaction.Tx
	Signature []byte
	TreeID    onet.TreeID
}

// CoSiTrees contains the encoded Tx.
type CoSiTrees struct {
	Message  []byte
	Transmit bool
}

// CoSiReplyTrees returns the signatures and the original message. Only used in testing
type CoSiReplyTrees struct {
	TreeIDS    []onet.TreeID
	Signatures [][]byte
	Message    []byte
}

// SubTreeArgs contains the arguments for the function GenerateSubTrees
type SubTreeArgs struct {
	Roster       *onet.Roster
	BF           int
	SubTreeCount int
}

// SubTreeReply contains the list of subtrees, their IDs and the complete roster
type SubTreeReply struct {
	Trees  []*onet.Tree
	IDs    []onet.TreeID
	Roster *onet.Roster
}

// GenesisArgs contains the arguments necessary to create a genesis Tx
type GenesisArgs struct {
	ID         []byte
	CoinID     []byte
	ReceiverPK []byte
}

// TxStorage is what is stored in boltdb's main bucket. It contains the transaction and its aggregate signatures
type TxStorage struct {
	Tx         transaction.Tx
	Signatures [][]byte
}

// MemoryRequest is handled by service function MemoryAllocated
type MemoryRequest struct{}

// MemoryReply contains the memory allocated for a service as well as the number of trees this service is a part of
type MemoryReply struct {
	BytesAllocated int
	NbrTrees       int
}
