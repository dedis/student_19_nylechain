package nylechain

import (
	"github.com/dedis/student_19_nylechain/service"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/onet/v3/log"
)

// Client is a structure to communicate with the template
// service
type Client struct {
	*onet.Client
}

// StoreTree stores the input tree in that ServerIdentity
func (c *Client) StoreTree(si *network.ServerIdentity, tree *onet.Tree) error {
	void := &service.VoidReply{}
	log.LLvl1("1")
	err := c.SendProtobuf(si, &service.StoreTreeArg{Tree: tree}, void)
	log.LLvl1("2")
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
	void := &service.VoidReply{}
	for _, si := range serverIDS {
		err := c.SendProtobuf(si, &service.SetupArgs{
			LocalityTrees: localityTrees, ServerIDS: serverIDS, Translations: translations,
		}, void)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenesisTx sends a GenesisArgs to every server. It returns an error if there was one for any of the servers.
func (c *Client) GenesisTx(servers []*onet.Server, id []byte, coinID []byte, receiverPK kyber.Point) error {
	void := &service.VoidReply{}
	for _, server := range servers {
		err := c.SendProtobuf(server.ServerIdentity, &service.GenesisArgs{
			ID: id, CoinID: coinID, ReceiverPK: receiverPK,
		}, void)
		if err != nil {
			return err
		}
	}
	return nil
}

// TreesBLSCoSi sends a CoSiTrees to the specified Server, and returns a CoSiReplyTrees or an eventual error.
func (c *Client) TreesBLSCoSi(si *network.ServerIdentity, trees []*onet.Tree, message []byte) (*service.CoSiReplyTrees, error) {
	reply := &service.CoSiReplyTrees{}
	err := c.SendProtobuf(si, &service.CoSiTrees{Trees: trees, Message: message}, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// NewClient instantiates a new template.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, service.ServiceName)}
}
