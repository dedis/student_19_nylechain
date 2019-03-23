package nylechain

import (
	"testing"

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
	msg := []byte("test")
	hosts, roster, _ := local.GenTree(9, true)

	defer local.CloseAll()
	services := local.GetServices(hosts, SimpleBLSCoSiID)

	subTreeReply, _ := GenerateSubTrees(&SubTreeArgs{
		Roster:       roster,
		BF:           2,
		SubTreeCount: 2,
	})

	coSiReplyTrees, _ := services[0].(*Service).TreesBLSCoSi(&CoSiTrees{
		Trees:   subTreeReply.Trees,
		Roster:  roster,
		Message: msg,
	})
	// subTreeReply and coSiReplyTrees contain respectively the trees and their signature in the same order.
	// Thus, we use i to access the tree corresponding to the signature, iterate on its roster to compute
	// aggPublic so that we can verify the signature in the end.
	for i, sig := range coSiReplyTrees.Signatures {
		aggPublic := testSuite.Point().Null()
		for _, r := range subTreeReply.Trees[i].Roster.List {
			aggPublic = aggPublic.Add(aggPublic, r.Public)
		}
		require.NoError(t, bls.Verify(testSuite, aggPublic, msg, sig))
	}
}
