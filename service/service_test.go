package service

import (
	_ "crypto/sha256"
	"sync"
	"testing"

	"github.com/dedis/student_19_nylechain/gentree"
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/kyber/v3/sign/bls"

	"go.dedis.ch/kyber/v3/pairing"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

/*func TestGenerateSubTrees(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	_, roster, _ := local.GenTree(20, true)
	defer local.CloseAll()
	subTreeReply, err := GenerateSubTrees(&SubTreeArgs{
		Roster:       roster,
		BF:           2,
		SubTreeCount: 3,
	})
	require.Nil(t, err)
	size := 0
	for _, tree := range subTreeReply.Trees {
		bool := size < tree.Size()
		require.True(t, bool)
		size = tree.Size()
	}

	subTreeReply, err = GenerateSubTrees(&SubTreeArgs{
		Roster:       roster,
		BF:           4,
		SubTreeCount: 1,
	})
	require.Nil(t, err)
	size = 0
	for _, tree := range subTreeReply.Trees {
		bool := size < tree.Size()
		require.True(t, bool)
		size = tree.Size()
	}
}*/
func TestTreesBLSCoSi(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	servers, roster, _ := local.GenTree(45, true)
	mapOfServers := make(map[string]*onet.Server)
	lc := gentree.LocalityContext{}
	lc.Setup(roster, "../nodeGen/nodes.txt")
	defer local.CloseAll()

	// Translating the trees into sets

	var fullTreeSlice []*onet.Tree

	for _, server := range servers {
		mapOfServers[server.ServerIdentity.String()] = server
	}

	for _, trees := range lc.LocalityTrees {
		for _, tree := range trees[1:] {
			fullTreeSlice = append(fullTreeSlice, tree)
			for _, serverIdentity := range tree.Roster.List {
				service := mapOfServers[serverIdentity.String()].Service(ServiceName).(*Service)
				marshalledTree, _ := tree.Marshal()
				service.StoreTree(&StoreTreeArg{
					MarshalledTree: marshalledTree,
					Roster:         tree.Roster,
				})
			}
		}
	}

	translations := TreesToSetsOfNodes(fullTreeSlice, roster.List)
	for _, server := range servers {
		service := server.Service(ServiceName).(*Service)
		service.Setup(&SetupArgs{
			ServerIDS:    roster.List,
			Translations: translations,
		})
	}

	PvK0, PbK0 := bls.NewKeyPair(testSuite, random.New())
	_, PbK1 := bls.NewKeyPair(testSuite, random.New())
	PubK0, _ := PbK0.MarshalBinary()
	PubK1, _ := PbK1.MarshalBinary()
	//_, PubK2 := bls.NewKeyPair(testSuite, random.New())
	iD0 := []byte("Genesis0")
	iD1 := []byte("Genesis1")
	coinID := []byte("0")
	coinID1 := []byte("1")

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

	/*innerAlt := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD0,
		SenderPK:   PubK0,
		ReceiverPK: PubK2,
	}
	innerEncodedAlt, _ := protobuf.Encode(&innerAlt)
	signatureAlt, _ := bls.Sign(testSuite, PrivK0, innerEncodedAlt)
	txAlt := transaction.Tx{
		Inner:     innerAlt,
		Signature: signatureAlt,
	}
	txEncodedAlt, _ := protobuf.Encode(&txAlt)*/

	for _, server := range servers {
		service := server.Service(ServiceName).(*Service)
		service.GenesisTx(&GenesisArgs{
			ID:         iD0,
			CoinID:     coinID,
			ReceiverPK: PubK0,
		})
		service.GenesisTx(&GenesisArgs{
			ID:         iD1,
			CoinID:     coinID1,
			ReceiverPK: PubK0,
		})
	}

	var wg sync.WaitGroup
	n := len(servers[:4])
	wg.Add(n)
	for _, server := range servers[:4] {
		go func(server *onet.Server) {
			// I exclude the first tree of every slice since it only contains one node
			trees := lc.LocalityTrees[lc.Nodes.GetServerIdentityToName(server.ServerIdentity)][1:]
			var treeIDs []onet.TreeID
			for _, tree := range trees {
				treeIDs = append(treeIDs, tree.ID)
				log.LLvl1(tree.Roster.List)
			}
			if len(trees) > 0 {
				// First valid Tx
				service := server.Service(ServiceName).(*Service)
				/*var w sync.WaitGroup
				w.Add(1)
				var err0 error
				go func() {*/
				service.TreesBLSCoSi(&CoSiTrees{
					TreeIDs: treeIDs,
					Message: txEncoded,
				})
				/*
						w.Done()
					}()
					// Double spending attempt
					_, err := service.TreesBLSCoSi(&CoSiTrees{
						TreeIDs:   treeIDs,
						Message: txEncodedAlt,
					})
					w.Wait()
					//log.LLvl1(err0)
					//log.LLvl1(err)
					if err0 == nil && err == nil {
						log.Fatal("Double spending accepted")
					}

					// Second valid Tx
					_, err = service.TreesBLSCoSi(&CoSiTrees{
						TreeIDs:   treeIDs,
						Message: txEncoded02,
					})*/
				//log.LLvl1(err)
			} else {
				log.LLvl1("0 TREE")
			}
			wg.Done()
		}(server)
	}

	wg.Wait()

	/*


		// We do a loop for each treeID. We first get the latest Tx in the second bucket by usinge the right TreeID and coinID,
		// then use that value to get the TxStorage in the first one. We then check that the stored senderPK is the right one.
		for i := 0; i < 9; i++ {
			services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
				b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
				v := b.Get(append([]byte(subTreeReply.IDs[2].String()), coinID...))
				b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
				v = b.Get(v)
				txStorage := TxStorage{}
				protobuf.Decode(v, &txStorage)
				require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK1))

				return nil
			})
		}

		for i := 0; i < 7; i++ {
			services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
				b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
				v := b.Get(append([]byte(subTreeReply.IDs[1].String()), coinID...))
				b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
				v = b.Get(v)
				txStorage := TxStorage{}
				protobuf.Decode(v, &txStorage)
				require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK1))

				return nil
			})
		}

		for i := 0; i < 3; i++ {
			services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
				b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
				v := b.Get(append([]byte(subTreeReply.IDs[0].String()), coinID...))
				b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
				v = b.Get(v)
				txStorage := TxStorage{}
				protobuf.Decode(v, &txStorage)
				require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK1))
				return nil
			})
		}*/

}
