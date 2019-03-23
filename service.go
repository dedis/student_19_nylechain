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
	if _, err := onet.GlobalProtocolRegister(protoName, simpleblscosi.NewDefaultProtocol); err != nil {
		log.ErrFatal(err)
	}
	SimpleBLSCoSiID, err = onet.RegisterNewService(serviceName, newService)
	log.ErrFatal(err)
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	db *bbolt.DB

	bucketNameTx     []byte
	bucketNameLastTx []byte

	propagateF messaging.PropagationFunc
}

// SimpleBLSCoSi starts a simpleblscosi-protocol and returns the final signature on the specified roster.
// The client chooses the message to be signed. It creates a binary tree then runs the protocol on it.
func (s *Service) SimpleBLSCoSi(cosi *CoSi) (*CoSiReply, error) {
	tree := cosi.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, errors.New("couldn't create tree")
	}
	pi, err := s.CreateProtocol(protoName, tree)
	if err != nil {
		return nil, err
	}
	pi.(*simpleblscosi.SimpleBLSCoSi).Message = cosi.Message
	pi.Start()
	reply := &CoSiReply{
		Signature: <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature,
		Message:   cosi.Message,
	}
	// s.startPropagation(s.propagateF, cosi.Roster, reply)
	return reply, nil
}

// NewDefaultProtocol is the default protocol function, with a verification function that checks transactions.
func (s *Service) NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	suite := pairing.NewSuiteBn256()
	// msg received is an encoded Tx struct
	vf := func(msg []byte) error {
		tx := transaction.Tx{}
		err := protobuf.Decode(msg, &tx)
		if err != nil {
			return err
		}

		// Verify that the signature was indeed produced by the sender
		inner, _ := protobuf.Encode(&tx.Inner)
		err = bls.Verify(suite, tx.Inner.SenderPK, inner, tx.Signature)
		if err != nil {
			return err
		}

		// Verify that the last transaction's receiver is the current transaction's sender
		s.db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(s.bucketNameTx)
			v := b.Get(tx.Inner.PreviousTx)
			prevTx := transaction.Tx{}
			err = protobuf.Decode(v, &prevTx)
			if err != nil {
				return err
			}
			if prevTx.Inner.ReceiverPK != tx.Inner.SenderPK {
				return errors.New("Previous transaction's receiver isn't current sender")
			}
			return nil
		})

		// Verify that the transaction is the last one of the chain
		s.db.View(func(bboltTx *bbolt.Tx) error {
			b := bboltTx.Bucket(s.bucketNameLastTx)
			v := b.Get(tx.Inner.CoinID)
			if bytes.Compare(v, msg) != 0 {
				return errors.New("This transaction is not the last of the chain")
			}
			return nil
		})

		return nil
	}
	return simpleblscosi.NewProtocol(n, vf, suite)
}

// TreesBLSCoSi is used when multiple trees are already constructed and runs the protocol on them concurrently.
// The signatures returned are ordered like the corresponding trees received.
func (s *Service) TreesBLSCoSi(args *CoSiTrees) (*CoSiReplyTrees, error) {
	tx := transaction.Tx{}
	err := protobuf.Decode(args.Message, &tx)
	if err != nil {
		return nil, err
	}
	// We send the initialization on the entire roster before sending signatures
	sha := sha256.New()
	sha.Write(args.Message)
	h := sha.Sum(nil)
	data := PropagateData{
		Initialization: true,
		TxID:           h,
		Tx:             tx,
	}
	s.startPropagation(s.propagateF, args.Roster, data)

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
				Initialization: false,
				TxID:           h,
				Signature:      <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature,
				CoinID:         tx.Inner.CoinID,
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

// propagateHandler receives a *PropagateData. It saves the transaction and its aggregate signatures in the "Tx"
// bucket, and tracks the last transaction for each coin in the "LastTx" bucket.
func (s *Service) propagateHandler(msg network.Message) {
	data := msg.(*PropagateData)
	// Initialization : the Tx is received but no aggregate signature yet, so we only store Tx.
	if data.Initialization {
		s.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(s.bucketNameTx)
			txStorage, err := protobuf.Encode(TxStorage{
				Tx: data.Tx,
			})
			if err != nil {
				return err
			}
			err = b.Put(data.TxID, txStorage)
			return err
		})
		return
	}

	// Non-initialization : we received a new aggregate structure that we need to store.
	s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucketNameTx)
		v := b.Get(data.TxID)
		storage := &TxStorage{}
		err := protobuf.Decode(v, storage)
		if err != nil {
			return err
		}
		storage.Signatures = append(storage.Signatures, data.Signature)
		storageEncoded, err := protobuf.Encode(storage)
		if err != nil {
			return err
		}
		err = b.Put(data.TxID, storageEncoded)
		if err != nil {
			return err
		}
		// Update LastTx bucket too
		b = tx.Bucket(s.bucketNameLastTx)
		err = b.Put(data.CoinID, data.TxID)
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

// GenerateSubTrees returns a list of nested trees, starting with the smallest one of height 1. The number of subtrees
// returned needs to be specified, as well as the branching factor. The first n-1 subtrees are all perfect trees while
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

	// We use the same formula again to specify the number of nodes for GenerateBigNaryTree. We iterate on the height.
	for i := 1; i <= args.SubTreeCount; i++ {
		n := int(math.Pow(float64(args.BF), float64(i+1))-1) / (args.BF - 1)
		newRoster := onet.NewRoster(args.Roster.List[:n])
		tree := newRoster.GenerateBigNaryTree(args.BF, n)
		trees = append(trees, tree)
	}

	fullTree := args.Roster.GenerateBigNaryTree(args.BF, len(args.Roster.List))
	trees = append(trees, fullTree)
	reply := &SubTreeReply{
		Trees:  trees,
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
	c.ProtocolRegister(protoName, s.NewDefaultProtocol)
	if err := s.RegisterHandler(s.SimpleBLSCoSi); err != nil {
		log.LLvl2(err)
		return nil, errors.New("Couldn't register message")
	}

	var err error
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
