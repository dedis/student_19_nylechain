package nylechain

import (
	"testing"

	"go.dedis.ch/protobuf"
	"go.etcd.io/bbolt"

	"github.com/dedis/student_19_nylechain/transaction"

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

func TestSimpleBLSCoSi(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	msg := []byte("message test")
	aggPublic := testSuite.Point().Null()
	hosts, roster, _ := local.GenTree(4, true)

	for _, r := range roster.List {
		aggPublic = aggPublic.Add(aggPublic, r.Public)
	}
	defer local.CloseAll()
	services := local.GetServices(hosts, SimpleBLSCoSiID)

	for _, s := range services {
		log.Lvl2("Sending request to", s)
		resp, err := s.(*Service).SimpleBLSCoSi(
			&CoSi{
				Roster:  roster,
				Message: msg,
			},
		)
		require.NoError(t, bls.Verify(testSuite, aggPublic, msg, resp.Signature))
		require.Nil(t, err)
	}
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
	PK0 := hosts[0].ServerIdentity.Public
	PK1 := hosts[1].ServerIdentity.Public
	iD := []byte("Genesis0")
	coinID := []byte("0")

	for _, s := range services {
		s.(*Service).GenesisTx(&GenesisArgs{
			ID:         iD,
			CoinID:     coinID,
			ReceiverPK: PK0,
		})
	}
	inner := transaction.InnerTx{
		CoinID:     coinID,
		PreviousTx: iD,
		SenderPK:   PK0,
		ReceiverPK: PK1,
	}
	innerEncoded, _ := protobuf.Encode(&inner)
	signature, _ := bls.Sign(testSuite, hosts[0].ServerIdentity.GetPrivate(), innerEncoded)
	tx := transaction.Tx{
		Inner:     inner,
		Signature: signature,
	}
	txEncoded, _ := protobuf.Encode(&tx)
	subTreeReply, _ := GenerateSubTrees(&SubTreeArgs{
		Roster:       roster,
		BF:           2,
		SubTreeCount: 2,
	})

	services[0].(*Service).TreesBLSCoSi(&CoSiTrees{
		Trees:   subTreeReply.Trees,
		Roster:  roster,
		Message: txEncoded,
	})
	for i := 0; i < 9; i++ {
		services[i].(*Service).db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(services[i].(*Service).bucketNameLastTx)
			v := b.Get(coinID)
			b = bboltTx.Bucket(services[i].(*Service).bucketNameTx)
			v = b.Get(v)
			txStorage := TxStorage{}
			protobuf.Decode(v, &txStorage)
			require.True(t, txStorage.Tx.Inner.SenderPK.Equal(PK0))

			return nil
		})
	}

}
