package nylechain

import (
	"testing"

	"go.dedis.ch/kyber/v3/sign/bls"

	"go.dedis.ch/kyber/v3/pairing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var tSuite = suites.MustFind("Ed25519")
var testSuite = pairing.NewSuiteBn256()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService_SimpleBLSCoSi(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	msg := []byte("message test")
	aggPublic := testSuite.Point().Null()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(5, true)

	log.LLvl2("hon")
	for _, r := range roster.List {
		aggPublic = aggPublic.Add(aggPublic, r.Public)
	}
	defer local.CloseAll()

	log.LLvl2("sa")
	services := local.GetServices(hosts, serviceID)

	for _, s := range services {
		log.Lvl2("Sending request to", s)
		signature, err := s.(*Service).SimpleBLSCoSi(roster, msg)
		require.NoError(t, bls.Verify(testSuite, aggPublic, msg, signature))
		require.Nil(t, err)
	}
}
