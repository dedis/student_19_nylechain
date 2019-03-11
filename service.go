package nylechain

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"crypto/sha256"
	"errors"
	"hash"
	"math"
	"time"

	"go.dedis.ch/cothority/v3/messaging"
	"go.dedis.ch/protobuf"

	"go.etcd.io/bbolt"

	"github.com/dedis/student_19_nylechain/simpleblscosi"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// SimpleBLSCoSiID is used for tests
var SimpleBLSCoSiID onet.ServiceID

const protoName = "simpleBLSCoSi"

func init() {
	var err error
	if _, err := onet.GlobalProtocolRegister(protoName, simpleblscosi.NewDefaultProtocol); err != nil {
		log.ErrFatal(err)
	}
	SimpleBLSCoSiID, err = onet.RegisterNewService("SimpleBLSCoSi", newService)
	log.ErrFatal(err)
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	db *bbolt.DB

	bucketName []byte

	hash256 hash.Hash

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
	s.startPropagation(s.propagateF, cosi.Roster, reply)
	return reply, nil
}

// TreesBLSCoSi is used when multiple trees are already constructed and runs the protocol on them.
func (s *Service) TreesBLSCoSi(args *CoSiTrees) (*CoSiReplyTrees, error) {
	var signatures [][]byte
	for _, tree := range args.Trees {
		pi, err := s.CreateProtocol(protoName, tree)
		if err != nil {
			return nil, err
		}
		pi.(*simpleblscosi.SimpleBLSCoSi).Message = args.Message
		pi.Start()
		reply := &CoSiReply{
			Signature: <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature,
			Message:   args.Message,
		}
		s.startPropagation(s.propagateF, tree.Roster, reply)
		signatures = append(signatures, reply.Signature)
	}
	return &CoSiReplyTrees{
		Signatures: signatures,
		Message:    args.Message,
	}, nil
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
		n := int(math.Pow(float64(args.BF), float64(i+1))-1)/(args.BF-1)
		newRoster := onet.NewRoster(args.Roster.List[:n])
		tree := newRoster.GenerateBigNaryTree(args.BF, n)
		trees = append(trees, tree)
	}

	fullTree := args.Roster.GenerateBigNaryTree(args.BF, len(args.Roster.List))
	trees = append(trees, fullTree)
	reply := &SubTreeReply{Trees: trees}
	return reply, nil
}

// propagateHandler receives a *CoSiReply containing both the initial message and the signature.
// It saves that CoSiReply in the service's bucket, keyed to a hash of the message.
func (s *Service) propagateHandler(reply network.Message) {
	message := reply.(*CoSiReply).Message
	s.hash256.Write(message)
	h := s.hash256.Sum(nil)
	s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(s.bucketName)
		replyBytes, err := protobuf.Encode(reply.(*CoSiReply))
		if err != nil {
			return err
		}
		err = b.Put(h, replyBytes)
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

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandler(s.SimpleBLSCoSi); err != nil {
		log.LLvl2(err)
		return nil, errors.New("Couldn't register message")
	}

	var err error
	s.propagateF, err = messaging.NewPropagationFunc(c, "Propagate", s.propagateHandler, -1)
	if err != nil {
		return nil, err
	}
	s.hash256 = sha256.New()
	db, bucketName := s.GetAdditionalBucket([]byte("bucket"))
	s.db = db
	s.bucketName = bucketName
	return s, nil
}
