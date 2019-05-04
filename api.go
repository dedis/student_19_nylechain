package nylechain

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

// Client is a structure to communicate with the template
// service
type Client struct {
	*onet.Client
}

// StoreTree stores the input tree in that ServerIdentity
func (c *Client) StoreTree(si *network.ServerIdentity, tree *onet.Tree) error {
	void := &VoidReply{}
	err := c.SendProtobuf(si, &StoreTreeArg{tree}, void)
	if err != nil {
		return err
	}
	return nil

}

// Setup sends a SetupArgs to every server. It returns an error if there was one for any of the servers.
func (c *Client) Setup(servers []*onet.Server, translations map[onet.TreeID][]byte,
	localityTrees map[string][]*onet.Tree) error {
	var serverIDS []*network.ServerIdentity
	for _, server := range servers {
		serverIDS = append(serverIDS, server.ServerIdentity)
	}
	void := &VoidReply{}
	for _, si := range serverIDS {
		err := c.SendProtobuf(si, &SetupArgs{localityTrees, serverIDS, translations}, void)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenesisTx sends a GenesisArgs to every server. It returns an error if there was one for any of the servers.
func (c *Client) GenesisTx(servers []*onet.Server, id []byte, coinID []byte, receiverPK kyber.Point) error {
	void := &VoidReply{}
	for _, server := range servers {
		err := c.SendProtobuf(server.ServerIdentity, &GenesisArgs{id, coinID, receiverPK}, void)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewClient instantiates a new template.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}
