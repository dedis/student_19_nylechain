package gentree

import (
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/network"
)

//Represents The actual graph that will be linked to the Binary Tree of the Protocol
type GraphTree struct {
	Tree        *onet.Tree
	ListOfNodes []*onet.TreeNode
	Parents     map[*onet.TreeNode][]*onet.TreeNode
}

type InitRequest struct {
	Nodes                []*LocalityNode
	ServerIdentityToName map[*network.ServerIdentity]string
	NrOps int
	OpIdxStart int
	Roster *onet.Roster
}


// SignatureResponse is what the Cosi service will reply to clients.
type InitResponse struct {
}

