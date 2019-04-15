package nylechain

import (
	"crypto/sha256"
	"testing"

	"github.com/dedis/student_19_nylechain/gentree"
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/kyber/v3/sign/bls"

	"go.dedis.ch/kyber/v3/pairing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestGenerateSubTrees(t *testing.T) {
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
}
func TestTreesBLSCoSi(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	servers, roster, _ := local.GenTree(45, true)
	mapOfServers := make(map[string]*onet.Server)
	for _, server := range servers {
		mapOfServers[server.ServerIdentity.String()] = server
	}
	defer local.CloseAll()

	lc := gentree.LocalityContext{}
	lc.Setup(roster, "nodeGen/nodes.txt")

	PrivK0, PubK0 := bls.NewKeyPair(testSuite, random.New())
	PrivK1, PubK1 := bls.NewKeyPair(testSuite, random.New())
	_, PubK2 := bls.NewKeyPair(testSuite, random.New())
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
	signature, _ := bls.Sign(testSuite, PrivK0, innerEncoded)
	tx := transaction.Tx{
		Inner:     inner,
		Signature: signature,
	}
	txEncoded, _ := protobuf.Encode(&tx)
	sha := sha256.New()
	sha.Write(txEncoded)
	iD01 := sha.Sum(nil)

	// Second transaction
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
	txEncoded02, _ := protobuf.Encode(&tx02)

	// First transaction of the second coin

	inner1 := transaction.InnerTx{
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
	txEncoded1, _ := protobuf.Encode(&tx1)

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

	for _, trees := range lc.LocalityTrees {
		log.LLvl1("------")
		for _, tree := range trees[1:] {
			log.LLvl1(tree.ID)
			log.LLvl1(tree.Roster.List)
			for _, serverIdentity := range tree.Roster.List {
				service := mapOfServers[serverIdentity.String()].Service(serviceName).(*Service)
				treeSlice := []*onet.Tree{tree}
				treeIDSlice := []onet.TreeID{tree.ID}
				service.StoreTrees(treeSlice)
				service.GenesisTx(&GenesisArgs{
					ID:         iD0,
					CoinID:     coinID,
					TreeIDs:    treeIDSlice,
					ReceiverPK: PubK0,
				})
				service.GenesisTx(&GenesisArgs{
					ID:         iD1,
					CoinID:     coinID1,
					TreeIDs:    treeIDSlice,
					ReceiverPK: PubK0,
				})
			}
		}
	}

	for _, server := range servers {
		trees := lc.LocalityTrees[lc.Nodes.GetServerIdentityToName(server.ServerIdentity)][1:]
		service := server.Service(serviceName).(*Service)
		service.TreesBLSCoSi(&CoSiTrees{
			Trees:   trees,
			Message: txEncoded,
		})
		service.TreesBLSCoSi(&CoSiTrees{
			Trees:   trees,
			Message: txEncoded1,
		})
		service.TreesBLSCoSi(&CoSiTrees{
			Trees:   trees,
			Message: txEncoded02,
		})
	}

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
