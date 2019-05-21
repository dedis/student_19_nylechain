package nylechain

import (
	"sync"

	"github.com/dedis/student_19_nylechain/service"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Client is a structure to communicate with the template
// service
type Client struct {
	*onet.Client
}

// Setup sends a SetupArgs to every server. It prints an error if there was one for any of the servers.
func (c *Client) Setup(roster *onet.Roster, translations map[onet.TreeID][]byte, distances map[string]map[string]float64) error {
	void := &service.VoidReply{}
	sArgs := &service.SetupArgs{
		Roster:       roster,
		Translations: translations,
		Distances:    distances,
	}
	var wg sync.WaitGroup
	wg.Add(len(roster.List))
	for _, si := range roster.List {
		go func(si *network.ServerIdentity) {
			err := c.SendProtobuf(si, sArgs, void)
			if err != nil {
				log.Fatal(err)
			}
			wg.Done()
		}(si)
	}
	wg.Wait()
	return nil
}

// GenesisTx sends a GenesisArgs to every server. It returns an error if there was one for any of the servers.
func (c *Client) GenesisTx(serverIDS []*network.ServerIdentity, id []byte, coinID []byte, rPK kyber.Point) error {
	void := &service.VoidReply{}
	receiverPK, err := rPK.MarshalBinary()
	if err != nil {
		return err
	}
	gArgs := &service.GenesisArgs{
		ID: id, CoinID: coinID, ReceiverPK: receiverPK,
	}
	for _, serverID := range serverIDS {
		err := c.SendProtobuf(serverID, gArgs, void)
		if err != nil {
			return err
		}
	}
	return nil
}

// TreesBLSCoSi sends a CoSiTrees to the specified Server, and returns a CoSiReplyTrees or an eventual error.
func (c *Client) TreesBLSCoSi(si *network.ServerIdentity, treeIDs []onet.TreeID, message []byte) (*service.CoSiReplyTrees, error) {
	reply := &service.CoSiReplyTrees{}
	err := c.SendProtobuf(si, &service.CoSiTrees{Message: message}, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// NewClient instantiates a new template.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, service.ServiceName)}
}
