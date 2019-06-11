package gentree

import (
	"testing"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

var testSuite = pairing.NewSuiteBn256()

func TestGenerateSubTrees(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	_, roster, _ := local.GenTree(90, true)
	defer local.CloseAll()

	lc := LocalityContext{}
	lc.Setup(roster, "../nodeGen/nodes.txt")

	for rootName, trees := range lc.LocalityTrees {
		for _, n := range trees {
			rosterNames := make([]string, 0)
			for _, si := range n.Roster.List {
				rosterNames = append(rosterNames, lc.Nodes.GetServerIdentityToName(si))
			}
			log.LLvl1("rootName ", rootName, "created onet locality tree with roster", rosterNames)
		}
	}

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
