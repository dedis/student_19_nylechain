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
		CoSi{}, CoSiReply{},
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

// PropagateData is what is received by propagateHandler. It's first received with argument initialization "true"
// and the Tx. Then, it will be received once for each new Signature. It's propagated by TreesBLSCoSi.
type PropagateData struct {
	Initialization bool
	TxID           []byte
	Tx             transaction.Tx
	Signature      []byte
	CoinID         []byte
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

// SubTreeReply contains the list of subtrees and the complete roster
type SubTreeReply struct {
	Trees  []*onet.Tree
	Roster *onet.Roster
}

// GenesisArgs contains the arguments necessary to create a genesis Tx
type GenesisArgs struct {
	ID         []byte
	CoinID     []byte
	ReceiverPK kyber.Point
}

// TxStorage is what is stored in boltdb. It contains the transaction and its aggregate signatures
type TxStorage struct {
	Tx         transaction.Tx
	Signatures [][]byte
}
