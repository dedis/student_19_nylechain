package nylechain

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"time"

	"go.dedis.ch/cothority/v3/messaging"
	"go.dedis.ch/protobuf"

	"go.etcd.io/bbolt"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"

	"github.com/dedis/student_19_nylechain/simpleblscosi"
	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// SimpleBLSCoSiID is used for tests
var SimpleBLSCoSiID onet.ServiceID

const protoName = "simpleBLSCoSi"
const serviceName = "SimpleBLSCoSi"

func init() {
	var err error
	SimpleBLSCoSiID, err = onet.RegisterNewService(serviceName, newService)
	log.ErrFatal(err)
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	db *bbolt.DB

	// Stores each transaction and its aggregate signatures (struct TxStorage), keyed to a hash of the encoded Tx.
	bucketNameTx []byte
	// Stores the last Tx, hashed (its key in the first bucket) for each CoinID and Tree,
	// keyed to a concatenation of TreeID + CoinID
	bucketNameLastTx []byte

	propagateF messaging.PropagationFunc
}

// vf checks transactions.
func (s *Service) vf(msg []byte, id onet.TreeID) error {
	tx := transaction.Tx{}
	err := protobuf.Decode(msg, &tx)
	if err != nil {
		return err
	}

	// Verify that the signature was indeed produced by the sender
	inner, _ := protobuf.Encode(&tx.Inner)

	suite := pairing.NewSuiteBn256()
	err = bls.Verify(suite, tx.Inner.SenderPK, inner, tx.Signature)
	if err != nil {
		return err
	}

	// Verify that the previous transaction is the last one of the chain
	err = s.db.View(func(bboltTx *bbolt.Tx) error {
		b := bboltTx.Bucket(s.bucketNameLastTx)
		v := b.Get(append([]byte(id.String()), tx.Inner.CoinID...))
		if bytes.Compare(v, tx.Inner.PreviousTx) != 0 {
			return errors.New("The previous transaction is not the last of the chain")
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Verify that the last transaction's receiver is the current transaction's sender
	err = s.db.View(func(bboltTx *bbolt.Tx) error {
		b := bboltTx.Bucket(s.bucketNameTx)
		v := b.Get(tx.Inner.PreviousTx)
		prevTx := transaction.Tx{}
		err = protobuf.Decode(v, &prevTx)
		if err != nil {
			return err
		}
		if !prevTx.Inner.ReceiverPK.Equal(tx.Inner.SenderPK) {
			return errors.New("Previous transaction's receiver isn't current sender")
		}
		return nil
	})

	return err
}

// NewDefaultProtocol is the default protocol function, with a verification function that checks transactions.
func (s *Service) NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	suite := pairing.NewSuiteBn256()
	return simpleblscosi.NewProtocol(n, s.vf, suite)
}

// GenesisTx creates and stores a genesis Tx with the specified ID (its key in the main bucket), CoinID and receiverPK.
// This will be the previousTx of the first real Tx, which needs it to pass the verification function.
// It also takes the IDs of the trees where the first Tx will be run, so that the genesis Tx can be stored
// as last transaction for each of the trees in the second boltdb bucket.
func (s *Service) GenesisTx(args *GenesisArgs) error {
	tx, err := protobuf.Encode(&transaction.Tx{Inner: transaction.InnerTx{ReceiverPK: args.ReceiverPK}})
	if err != nil {
		return err
	}
	err = s.db.Update(func(bboltTx *bbolt.Tx) error {
		// Store in the main bucket
		b := bboltTx.Bucket(s.bucketNameTx)
		err = b.Put(args.ID, tx)
		if err != nil {
			return err
		}
		// Store as last transaction in the LastTx bucket for every TreeID
		b = bboltTx.Bucket(s.bucketNameLastTx)
		for _, id := range args.TreeIDs {
			err = b.Put(append([]byte(id.String()), args.CoinID...), args.ID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// TreesBLSCoSi is used when multiple trees are already constructed and runs the protocol on them concurrently.
// The "Message" argument is always an encoded transaction.
// It propagates the transaction and the aggregate signatures so that they're stored.
// The signatures returned are ordered like the corresponding trees received.
func (s *Service) TreesBLSCoSi(args *CoSiTrees) (*CoSiReplyTrees, error) {
	tx := transaction.Tx{}
	err := protobuf.Decode(args.Message, &tx)
	if err != nil {
		return nil, err
	}
	// We send the initialization on the entire roster before sending signatures
	data := PropagateData{Tx: tx}

	s.startPropagation(s.propagateF, args.Roster, &data)

	var wg sync.WaitGroup
	n := len(args.Trees)
	wg.Add(n)
	signatures := make([][]byte, n)
	for i, tree := range args.Trees {
		go func(i int, tree *onet.Tree) {
			defer wg.Done()
			pi, _ := s.CreateProtocol(protoName, tree)
			pi.(*simpleblscosi.SimpleBLSCoSi).Message = args.Message
			pi.Start()
			// Send signatures one by one after the initialization
			data := &PropagateData{
				Tx:        tx,
				Signature: <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature,
				// Tree:      tree,
				TreeID:    tree.ID,
			}
			// Only propagate to that specific tree's roster
			s.startPropagation(s.propagateF, tree.Roster, data)
			signatures[i] = data.Signature
		}(i, tree)
	}
	wg.Wait()
	return &CoSiReplyTrees{
		Signatures: signatures,
		Message:    args.Message,
	}, nil
}

// propagateHandler receives a *PropagateData. It stores the transaction and its aggregate signatures in the "Tx"
// bucket, and tracks the last transaction for each coin and tree in the "LastTx" bucket.
func (s *Service) propagateHandler(msg network.Message) {
	data := msg.(*PropagateData)
	txEncoded, err := protobuf.Encode(&data.Tx)
	sha := sha256.New()
	sha.Write(txEncoded)
	h := sha.Sum(nil)

	s.db.Update(func(bboltTx *bbolt.Tx) error {
		b := bboltTx.Bucket(s.bucketNameTx)
		v := b.Get(h)
		// Initialization : we only store Tx and no signature
		// We don't store it as "LastTx" yet : we wait for an aggregate signature.
		if v == nil {
			txStorage, err := protobuf.Encode(&TxStorage{
				Tx: data.Tx,
			})
			if err != nil {
				return err
			}
			err = b.Put(h, txStorage)
			return err
		}
		// Non-initialization : we received a new aggregate structure that we need to store.

		// First check that Tx is valid with the vf
		err = s.vf(txEncoded, data.TreeID)
		if err != nil {
			return err
		}

		// Then check the aggregate signature

		/*
			suite := pairing.NewSuiteBn256()
			err = bls.Verify(suite, data.Tree.Root.AggregatePublic(suite), txEncoded, data.Signature)
			if err != nil {
				return err
			}
		*/

		// Store the aggregate signature
		storage := &TxStorage{}
		err = protobuf.Decode(v, storage)
		if err != nil {
			return err
		}
		storage.Signatures = append(storage.Signatures, data.Signature)
		storageEncoded, err := protobuf.Encode(storage)
		if err != nil {
			return err
		}
		err = b.Put(h, storageEncoded)
		if err != nil {
			return err
		}
		// Update LastTx bucket too
		b = bboltTx.Bucket(s.bucketNameLastTx)
		err = b.Put(append([]byte(data.TreeID.String()), data.Tx.Inner.CoinID...), h)
		return err
	})
	return

}

func (s *Service) startPropagation(propagate messaging.PropagationFunc, ro *onet.Roster, msg network.Message) error {

	replies, err := propagate(ro, msg, 10*time.Second)
	if err != nil {
		return err
	}

	if replies != len(ro.List) {
		log.Lvl1(s.ServerIdentity(), "Only got", replies, "out of", len(ro.List))
	}

	return nil
}

// GenerateSubTrees returns a list of nested trees and their IDs, starting with the smallest one of height 1.
// The number of subtrees returned needs to be specified, as well as the branching factor.
// The first n-1 subtrees are all perfect trees while
// the last one is the full tree which uses every server of the specified rosters.
// Each tree is a subtree of every following tree in the list.
func GenerateSubTrees(args *SubTreeArgs) (*SubTreeReply, error) {
	if args.SubTreeCount < 1 {
		return nil, errors.New("SubTreeCount must be positive")
	}

	// The formula of the total number of nodes of a perfect k-ary tree is used to determine if the roster is large enough
	// to return enough perfect subtrees. SubTreeCount is equal to the height of the largest subtree, which needs to
	// have less total nodes that the full tree.
	if (int(math.Pow(float64(args.BF), float64(args.SubTreeCount+1))-1) / (args.BF - 1)) >= len(args.Roster.List) {
		return nil, errors.New("SubTreeCount too high/ Roster too small")
	}
	var trees []*onet.Tree
	var ids []onet.TreeID

	// We use the same formula again to specify the number of nodes for GenerateBigNaryTree. We iterate on the height.
	for i := 1; i <= args.SubTreeCount; i++ {
		n := int(math.Pow(float64(args.BF), float64(i+1))-1) / (args.BF - 1)
		newRoster := onet.NewRoster(args.Roster.List[:n])
		tree := newRoster.GenerateBigNaryTree(args.BF, n)
		trees = append(trees, tree)
		ids = append(ids, tree.ID)
	}

	fullTree := args.Roster.GenerateBigNaryTree(args.BF, len(args.Roster.List))
	trees = append(trees, fullTree)
	ids = append(ids, fullTree.ID)
	reply := &SubTreeReply{
		Trees:  trees,
		IDs:    ids,
		Roster: args.Roster,
	}
	return reply, nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	_, err := c.ProtocolRegister(protoName, s.NewDefaultProtocol)
	if err != nil {
		return nil, err
	}

	s.propagateF, err = messaging.NewPropagationFunc(c, "Propagate", s.propagateHandler, -1)
	if err != nil {
		return nil, err
	}
	db, bucketNameTx := s.GetAdditionalBucket([]byte("Tx"))
	_, bucketNameLastTx := s.GetAdditionalBucket([]byte("LastTx"))
	s.bucketNameTx = bucketNameTx
	s.bucketNameLastTx = bucketNameLastTx
	s.db = db
	return s, nil
}
