package nylechain

import (
	"testing"

	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/protobuf"
	"go.etcd.io/bbolt"

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
	hosts, roster, _ := local.GenTree(9, true)
	defer local.CloseAll()
	services := local.GetServices(hosts, SimpleBLSCoSiID)

	subTreeReply, _ := GenerateSubTrees(&SubTreeArgs{
		Roster:       roster,
		BF:           2,
		SubTreeCount: 2,
	})
	PrivK0, PubK0 := bls.NewKeyPair(testSuite, random.New())
	_, PubK1 := bls.NewKeyPair(testSuite, random.New())
	iD := []byte("Genesis0")
	coinID := []byte("0")

	for _, s := range services {
		s.(*Service).GenesisTx(&GenesisArgs{
			ID:         iD,
			CoinID:     coinID,
			TreeIDs:    subTreeReply.IDs,
			ReceiverPK: PubK0,
		})
	}
	inner := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD,
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

	services[0].(*Service).TreesBLSCoSi(&CoSiTrees{
		Trees:   subTreeReply.Trees,
		Roster:  roster,
		Message: txEncoded,
	})
	for i := 0; i < 9; i++ {
		services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
			v := b.Get(append([]byte(subTreeReply.Trees[2].ID.String()), coinID...))
			b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
			v = b.Get(v)
			txStorage := TxStorage{}
			protobuf.Decode(v, &txStorage)
			require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK0))

			return nil
		})
	}

	for i := 0; i < 7; i++ {
		services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
			v := b.Get(append([]byte(subTreeReply.Trees[1].ID.String()), coinID...))
			b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
			v = b.Get(v)
			txStorage := TxStorage{}
			protobuf.Decode(v, &txStorage)
			require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK0))

			return nil
		})
	}

	for i := 0; i < 3; i++ {
		services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
			v := b.Get(append([]byte(subTreeReply.Trees[0].ID.String()), coinID...))
			b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
			v = b.Get(v)
			txStorage := TxStorage{}
			protobuf.Decode(v, &txStorage)
			require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PubK0))
			return nil
		})
	}

}
