package gentree

import (
	"testing"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/kyber.v2/group/edwards25519"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

var testSuite = edwards25519.NewBlakeSHA256Ed25519()

func TestGenerateSubTrees(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	_, roster, _ := local.GenTree(45, true)
	defer local.CloseAll()

	lc := LocalityContext{}
	lc.Setup(roster, "../nodeGen/nodes.txt")

	/*
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
	*/
}
