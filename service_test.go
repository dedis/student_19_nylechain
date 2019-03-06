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

func TestService(t *testing.T) {
	local := onet.NewTCPTest(testSuite)
	msg := []byte("message test")
	aggPublic := testSuite.Point().Null()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(20, true)

	for _, r := range roster.List {
		aggPublic = aggPublic.Add(aggPublic, r.Public)
	}
	defer local.CloseAll()
	services := local.GetServices(hosts, SimpleBLSCoSiID)

	for _, s := range services {
		//log.Lvl2("Sending request to", s)
		resp, err := s.(*Service).SimpleBLSCoSi(
			&CoSi{
				Roster:  roster,
				Message: msg,
			},
		)
		require.NoError(t, bls.Verify(testSuite, aggPublic, msg, resp.Signature))
		require.Nil(t, err)
	}

	reply, _ := services[0].(*Service).GenerateSubTrees(
		&SubTreeArgs{
			Roster: roster,
			BF: 3,
			SubTreeCount: 2,
		},
	)
	for _, tree := range reply.Trees {
		log.LLvl1("size :")
		log.LLvl1(tree.Size())
		log.LLvl1("-")
		//services[0].(*Service).TreeBLSCoSi(&CoSiTree{
		//	Tree: tree,
		//	Message: msg,
		//})

		for _, node := range tree.List() {
			log.LLvl1(node.RosterIndex)
			if node.Parent != nil {
				log.LLvl1(node.Parent.RosterIndex)
			}
			log.LLvl1("---")
		}
	}

}
