package main

import (
	_ "os"
	"time"

	"github.com/BurntSushi/toml"
	nylechain "github.com/dedis/student_19_nylechain"
	"github.com/dedis/student_19_nylechain/gentree"
	"github.com/dedis/student_19_nylechain/service"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	_ "go.dedis.ch/onet/v3/simul/monitor"
)

/*
 * Defines the simulation for the service-template
 */

func init() {
	onet.SimulationRegister("NylechainService", NewSimulationService)
}

// SimulationService only holds the BFTree simulation
type SimulationService struct {
	onet.SimulationBFTree
}

// NewSimulationService returns the new simulation, where all fields are
// initialised using the config-file
func NewSimulationService(config string) (onet.Simulation, error) {
	es := &SimulationService{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (s *SimulationService) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}

	log.Lvl3("Initializing node-index", index)

	return s.SimulationBFTree.Node(config)
}

// Run is used on the destination machines and runs a number of
// rounds
func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)

	c := nylechain.NewClient()

	var fullTreeSlice []*onet.Tree
	serverIDS := config.Roster.List
	lc := gentree.LocalityContext{}
	//crt, _ := os.Getwd()
	//log.LLvl1("!!!!!!!!!!!!!!!!!!!", crt)

	// TODO path to use when running simulation test
	lc.Setup(config.Roster, "../../nodeGen/nodes.txt")

	// TODO path to use when running api test
	// lc.Setup(config.Roster, "nodeGen/nodes.txt")

	for _, trees := range lc.LocalityTrees {
		for _, tree := range trees[1:] {
			fullTreeSlice = append(fullTreeSlice, tree)
		}
	}

	// Create a matrix of distances between serverIdentities
	distances := service.CreateMatrixOfDistances(serverIDS, lc.Nodes)

	translations := service.TreesToSetsOfNodes(fullTreeSlice, config.Roster.List)
	err := c.Setup(config.Roster, translations, distances)
	log.ErrFatal(err)

	// Genesis of 2 different coins
	suite := pairing.NewSuiteBn256()
	PvK0, PbK0 := bls.NewKeyPair(suite, random.New())
	/*_, PbK1 := bls.NewKeyPair(suite, random.New())
	//_, PubK2 := bls.NewKeyPair(testSuite, random.New())
	PubK0, _ := PbK0.MarshalBinary()
	PubK1, _ := PbK1.MarshalBinary()*/
	iD0 := []byte("Genesis0")
	//iD1 := []byte("Genesis1")
	coinID := []byte("0")
	//coinID1 := []byte("1")

	err = c.GenesisTx(serverIDS, iD0, coinID, PbK0)
	log.ErrFatal(err)
	/*err = c.GenesisTx(serverIDS, iD1, coinID1, PbK0)
	log.ErrFatal(err)

	// First transaction
	inner := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD0,
		SenderPK:   PubK0,
		ReceiverPK: PubK1,
	}
	innerEncoded, _ := protobuf.Encode(&inner)
	signature, _ := bls.Sign(suite, PvK0, innerEncoded)
	tx := transaction.Tx{
		Inner:     inner,
		Signature: signature,
	}
	txEncoded, _ := protobuf.Encode(&tx)*/
	txs, err := service.TxChain(1, PbK0, PvK0, iD0, coinID)
	log.ErrFatal(err)
	start := time.Now()
	sid := serverIDS[44]
	rootName := lc.Nodes.GetServerIdentityToName(sid)
	for i, tx := range txs {
		_, err = c.TreesBLSCoSi(sid, tx)
		log.LLvl1(i)
		log.ErrFatal(err)
	}
	t := time.Now()
	elapsed := t.Sub(start)
	averageMemories, err := c.RequestMemoryAllocated(serverIDS)
	log.ErrFatal(err)

	log.LLvl1("-----------------")
	for _, n := range lc.LocalityTrees[rootName][1:] {
		log.LLvl1(rootName, "is the root of a tree with ", len(n.Roster.List), "nodes.")
	}
	log.LLvl1("-----------------")

	log.LLvl1("Time to execute ", len(txs), " Tx(s) :", elapsed)
	log.LLvl1("-----------------")
	for i := 1; i < 30; i++ {
		if averageMemories[i] > 0 {
			log.LLvl1(i, "trees : ", averageMemories[i], " bytes")
		}
	}
	log.LLvl1("-----------------")
	return nil
}
