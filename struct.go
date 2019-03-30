package nylechain

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(
		SubTreeArgs{}, SubTreeReply{},
		CoSiTrees{}, CoSiReplyTrees{},
		TxStorage{}, PropagateData{},
		GenesisArgs{},
	)
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// PropagateData is what is received by propagateHandler. It's propagated by TreesBLSCoSi.
type PropagateData struct {
	Tx        transaction.Tx
	Signature []byte
	Tree    *onet.Tree
}

// CoSiTrees contains multiple trees and the complete roster.
type CoSiTrees struct {
	Trees   []*onet.Tree
	Roster  *onet.Roster
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
	TreeIDs    []onet.TreeID
	ReceiverPK kyber.Point
}

// TxStorage is what is stored in boltdb's main bucket. It contains the transaction and its aggregate signatures
type TxStorage struct {
	Tx         transaction.Tx
	Signatures [][]byte
}
