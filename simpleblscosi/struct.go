package simpleblscosi

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&SimplePrepare{}, &SimplePrepareReply{},
		&SimpleCommit{}, &SimpleCommitReply{}, &TransmitError{}, &Shutdown{})
}

// Prepare phase

// SimplePrepare is used to pass a message which all the nodes should vote on.
type SimplePrepare struct {
	Message []byte
}

// prepareChan wraps SimplePrepare for onet.
type prepareChan struct {
	*onet.TreeNode
	SimplePrepare
}

// SimplePrepareReply is the signature or aggregate signature on the message.
type SimplePrepareReply struct {
	PosSig []byte
	NegSig []byte
}

// prepareReplyChan wraps SimplePrepareReply for onet.
type prepareReplyChan struct {
	*onet.TreeNode
	SimplePrepareReply
}

// Commit phase

// SimpleCommit is to commit the (hashed) prepared message.
type SimpleCommit struct {
	PosAggrSig []byte
	NegAggrSig []byte
}

// commitChan wraps SimpleCommit for onet.
type commitChan struct {
	*onet.TreeNode
	SimpleCommit
}

// SimpleCommitReply is the (aggregate) signature for the commit message.
type SimpleCommitReply struct {
	PosSig []byte
	NegSig []byte
}

// commitReplyChan wraps SimpleCommitReply for onet.
type commitReplyChan struct {
	*onet.TreeNode
	SimpleCommitReply
}

// TransmitError transmits the error to the root
type TransmitError struct {
	Error string
}

// errorChan wraps TransmitError for onet.
type errorChan struct {
	*onet.TreeNode
	TransmitError
}

// Shutdown is called when the root received an error, it goes down the tree shutting everything down
type Shutdown struct {
	Error string
}

// shutdownChan wraps Shutdown for onet.
type shutdownChan struct {
	*onet.TreeNode
	Shutdown
}
