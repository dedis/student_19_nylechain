package nylechain

import (
	"sync"
	"testing"

	"go.dedis.ch/onet/v3/network"

	"go.dedis.ch/kyber/v3/pairing"

	"github.com/dedis/protobuf"
	"github.com/dedis/student_19_nylechain/gentree"
	"github.com/dedis/student_19_nylechain/service"
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestClientTreesBLSCoSi(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	servers, roster, _ := local.GenTree(45, true)
	lc := gentree.LocalityContext{}
	lc.Setup(roster, "nodeGen/nodes.txt")
	defer local.CloseAll()

	c := NewClient()

	// Translating the trees into sets

	var fullTreeSlice []*onet.Tree
	var serverIDS []*network.ServerIdentity
	for _, server := range servers {
		serverIDS = append(serverIDS, server.ServerIdentity)
		server.Service(service.ServiceName).(*service.Service).Lc = lc
	}

	for _, trees := range lc.LocalityTrees {
		for _, tree := range trees[1:] {
			fullTreeSlice = append(fullTreeSlice, tree)
		}
	}

	translations := service.TreesToSetsOfNodes(fullTreeSlice, roster.List)
	distances := service.CreateMatrixOfDistances(serverIDS, lc.Nodes)
	err := c.Setup(roster, translations, distances)
	log.ErrFatal(err)

	// Genesis of 2 different coins

	PvK0, PbK0 := bls.NewKeyPair(testSuite, random.New())
	_, PbK1 := bls.NewKeyPair(testSuite, random.New())
	_, PbK2 := bls.NewKeyPair(testSuite, random.New())
	PubK0, _ := PbK0.MarshalBinary()
	PubK1, _ := PbK1.MarshalBinary()
	PubK2, _ := PbK2.MarshalBinary()
	//_, PubK2 := bls.NewKeyPair(testSuite, random.New())
	iD0 := []byte("Genesis0")
	iD1 := []byte("Genesis1")
	coinID := []byte("0")
	coinID1 := []byte("1")

	err = c.GenesisTx(serverIDS, iD0, coinID, PbK0)
	log.ErrFatal(err)
	err = c.GenesisTx(serverIDS, iD1, coinID1, PbK0)
	log.ErrFatal(err)

	// First transaction
	inner := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD0,
		SenderPK:   PubK0,
		ReceiverPK: PubK1,
	}
	innerEncoded, _ := protobuf.Encode(&inner)
	signature, _ := bls.Sign(testSuite, PvK0, innerEncoded)
	tx := transaction.Tx{
		Inner:     inner,
		Signature: signature,
	}
	txEncoded, _ := protobuf.Encode(&tx)

	// Second transaction

	/*sha := sha256.New()
	sha.Write(txEncoded)
	iD01 := sha.Sum(nil)
	inner02 := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD01,
		SenderPK:   PubK1,
		ReceiverPK: PubK2,
	}
	innerEncoded02, _ := protobuf.Encode(&inner02)
	signature02, _ := bls.Sign(testSuite, PrivK1, innerEncoded02)
	tx02 := transaction.Tx{
		Inner:     inner02,
		Signature: signature02,
	}
	txEncoded02, _ := protobuf.Encode(&tx02)*/

	// First transaction of the second coin

	/*inner1 := transaction.InnerTx{
		CoinID:     coinID1,
		PreviousTx: iD1,
		SenderPK:   PubK0,
		ReceiverPK: PubK1,
	}
	innerEncoded1, _ := protobuf.Encode(&inner1)
	signature1, _ := bls.Sign(testSuite, PrivK0, innerEncoded1)
	tx1 := transaction.Tx{
		Inner:     inner1,
		Signature: signature1,
	}
	txEncoded1, _ := protobuf.Encode(&tx1)*/

	// Alternative first Tx of coin 0 sending to PubK2 instead of PubK1

	innerAlt := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD0,
		SenderPK:   PubK0,
		ReceiverPK: PubK2,
	}
	innerEncodedAlt, _ := protobuf.Encode(&innerAlt)
	signatureAlt, _ := bls.Sign(testSuite, PvK0, innerEncodedAlt)
	txAlt := transaction.Tx{
		Inner:     innerAlt,
		Signature: signatureAlt,
	}
	txEncodedAlt, _ := protobuf.Encode(&txAlt)

	var wg sync.WaitGroup
	n := len(servers[:3])
	wg.Add(n)
	for _, server := range servers[:3] {
		go func(server *onet.Server) {
			// I exclude the first tree of every slice since it only contains one node
			trees := lc.LocalityTrees[lc.Nodes.GetServerIdentityToName(server.ServerIdentity)][1:]
			/*for _, tree := range trees {
				for _, id := range tree.Roster.List {
					log.LLvl1(id.String()[len(id.String())-2:])
				}
				log.LLvl1("---")
			}*/
			if len(trees) > 0 {
				// First valid Tx
				var w sync.WaitGroup
				w.Add(1)
				var err0 error
				go func() {
					_, err0 = c.TreesBLSCoSi(server.ServerIdentity, txEncoded)

					w.Done()
				}()
				// Double spending attempt
				_, err := c.TreesBLSCoSi(server.ServerIdentity, txEncodedAlt)
				w.Wait()
				log.LLvl1(err0)
				log.LLvl1(err)
				if err0 == nil && err == nil {
					log.Fatal("Double spending accepted")
				}

				// Second valid Tx
				//_, err = c.TreesBLSCoSi(server.ServerIdentity, treeIDs, )
				//log.LLvl1(err)
			}
			wg.Done()
		}(server)
	}

	wg.Wait()

}
