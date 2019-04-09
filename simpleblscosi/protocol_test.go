package simpleblscosi

/*

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"testing"
	"time"
)

const protoName = "testProtocol"

var testSuite = pairing.NewSuiteBn256()

func testProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a []byte, id onet.TreeID) error { return nil }
	return NewProtocol(n, vf, testSuite)
}

func init() {
	if _, err := onet.GlobalProtocolRegister(protoName, testProtocol); err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestCosi(t *testing.T) {
	for _, nbrHosts := range []int{4, 7} {
		log.Lvl2("Running cosi with", nbrHosts, "hosts")
		local := onet.NewLocalTest(testSuite)
		_, el, tree := local.GenBigTree(nbrHosts, nbrHosts, 3, true)
		aggPublic := testSuite.Point().Null()
		for _, e := range el.List {
			aggPublic = aggPublic.Add(aggPublic, e.Public)
		}

		// create the message we want to sign for this round
		msg := []byte("Hello World Cosi")

		// Register the function generating the protocol instance
		var root *SimpleBLSCoSi

		// Start the protocol
		p, err := local.CreateProtocol(protoName, tree)
		if err != nil {
			t.Fatal("Couldn't create new node:", err)
		}
		root = p.(*SimpleBLSCoSi)
		root.Message = msg
		go func() {
			err := root.Start()
			require.NoError(t, err)
		}()
		select {
		case sig := <-root.FinalSignature:
			require.NoError(t, bls.Verify(testSuite, aggPublic, msg, sig))
		case <-time.After(time.Second * 2):
			t.Fatal("Could not get signature verification done in time")
		}

		local.CloseAll()
	}
}
*/
