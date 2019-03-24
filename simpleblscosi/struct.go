package simpleblscosi

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(&SimplePrepare{}, &SimplePrepareReply{},
		&SimpleCommit{}, &SimpleCommitReply{})
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
	Sig []byte
}

// prepareReplyChan wraps SimplePrepareReply for onet.
type prepareReplyChan struct {
	*onet.TreeNode
	SimplePrepareReply
}

// Commit phase

// SimpleCommit is to commit the (hashed) prepared message.
type SimpleCommit struct {
	AggrSig []byte
}

// commitChan wraps SimpleCommit for onet.
type commitChan struct {
	*onet.TreeNode
	SimpleCommit
}

// SimpleCommitReply is the (aggregate) signature for the commit message.
type SimpleCommitReply struct {
	Sig []byte
}

// commitReplyChan wraps SimpleCommitReply for onet.
type commitReplyChan struct {
	*onet.TreeNode
	SimpleCommitReply
}

