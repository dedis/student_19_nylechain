package service

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
	"sync/atomic"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"

	"github.com/dedis/student_19_nylechain/gentree"

	"go.dedis.ch/cothority/v3"

	"github.com/dedis/student_19_nylechain/propagate"
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

// ServiceName is also used in api.go for example
const ServiceName = "SimpleBLSCoSi"

var cosiSendRawID network.MessageTypeID

func init() {
	cosiSendRawID = network.RegisterMessage(&CoSiSendRaw{})
	var err error
	SimpleBLSCoSiID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	Lc gentree.LocalityContext

	// The IDs of roots of trees this node is a part of, except this node's server ID.
	rootsIDs []*network.ServerIdentity

	distances map[string]map[string]float64

	// Complete list of the Server Identities
	orderedServerIdentities []*network.ServerIdentity

	// Trees of which this server is a part of, keyed to TreeID
	trees map[onet.TreeID]*onet.Tree

	// Complete list of translation from a Tree to its ordered set
	treeIDSToSets map[onet.TreeID][]byte

	// Keys are concatenations of TreeID + CoinID
	coinToAtomic       map[string]int
	atomicCoinReserved []int32

	db *bbolt.DB

	// Stores each transaction and its aggregate signatures (struct TxStorage), keyed to a hash of the encoded Tx.
	bucketNameTx []byte

	// Stores the last Tx, hashed (its key in the first bucket) for each Tree and CoinID,
	// keyed to a concatenation of TreeID + CoinID
	bucketNameLastTx []byte

	propagateF propagate.PropagationFunc
	mypi       func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error)
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
	senderPK := suite.G2().Point()
	err = senderPK.UnmarshalBinary(tx.Inner.SenderPK)
	if err != nil {
		return err
	}
	err = bls.Verify(suite, senderPK, inner, tx.Signature)
	if err != nil {
		return errors.New("This signature wasn't produced by the sender")
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
		storage := TxStorage{}
		err = protobuf.Decode(v, &storage)
		if err != nil {
			return err
		}
		if bytes.Compare(storage.Tx.Inner.ReceiverPK, tx.Inner.SenderPK) != 0 {
			return errors.New("Previous transaction's receiver isn't current sender")
		}
		return nil
	})
	return err
}

// IsSubSetOfNodes returns if subID's set is a strict subset of fullID's set of nodes.
// Since fullSet and subSet both are slices of increasing indexes of nodes, we need to check that every index in subSet is in fullSet.
// Example : [byte(0), byte(3)] is a subset of [byte(0), byte(1), by byte(3)]
func (s *Service) IsSubSetOfNodes(fullID onet.TreeID, subID onet.TreeID) (bool, error) {
	fullSet := s.treeIDSToSets[fullID]
	subSet := s.treeIDSToSets[subID]
	if fullSet == nil || subSet == nil {
		return false, errors.New("TreeID not stored in this service")
	}
	if bytes.Equal(fullSet, subSet) {
		return false, nil
	}
	fullIndex := 0
	// We scan both byte slices from left to right, exploiting the fact that the bytes are in increasing order
	for _, subNode := range subSet {
		if fullIndex == len(fullSet) {
			// We already scanned the entire fullSet
			return false, nil
		}
		for i := fullIndex; i < len(fullSet); i++ {
			fullIndex++
			if fullSet[i] == subNode {
				// We go the the next subNode
				break
			}
			if fullSet[i] > subNode {
				// We can immediatly conclude that subNode is not in fullSet
				return false, nil
			}
			if fullIndex == len(fullSet) {
				// The last node of fullSet wasn't subNode
				return false, nil
			}
		}
	}
	// Every node of subSet is in fullSet
	return true, nil
}

// NewDefaultProtocol is the default protocol function, with a verification function that checks transactions.
func (s *Service) NewDefaultProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	suite := pairing.NewSuiteBn256()
	return simpleblscosi.NewProtocol(n, s.vf, n.Tree().ID, s.atomicCoinReserved, s.coinToAtomic, s.distances, suite)
}

// NewProtocol is an override. It's called on children automatically
func (s *Service) NewProtocol(n *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	switch n.ProtocolName() {
	case protoName:
		suite := pairing.NewSuiteBn256()
		return simpleblscosi.NewProtocol(n, s.vf, n.Tree().ID, s.atomicCoinReserved, s.coinToAtomic, s.distances, suite)
	case "Propagate":
		return s.mypi(n)
	default:
		return nil, errors.New("This protocol does not exist")
	}
}

// Setup stores the ordered slice of Server Identities, the translations from Trees to Sets of nodes and the distances between servers.
func (s *Service) Setup(args *SetupArgs) (*VoidReply, error) {
	lc := gentree.LocalityContext{}

	//crt, _ := os.Getwd()
	//log.LLvl1(crt)
	// TODO use when calling simulation test
	lc.Setup(args.Roster, "../../nodeGen/nodes.txt")

	// TODO path to use when running api test
	//lc.Setup(args.Roster, "nodeGen/nodes.txt")

	// TODO path to use when running service test
	//lc.Setup(args.Roster, "../nodeGen/nodes.txt")

	s.Lc = lc

	// We store every tree this node is a part of in s.trees, as well as the different roots's ID's of those trees in s.rootsIDs
	for rootName, trees := range lc.LocalityTrees {
		// this bool is used to know if this root has a tree which contains the current service
		isRootLinked := false
		for _, tree := range trees[1:] {
			for _, si := range tree.Roster.List {
				if si.Equal(s.ServerIdentity()) {
					s.trees[tree.ID] = tree
					isRootLinked = true
					break
				}
			}
		}
		if isRootLinked {
			sID := lc.Nodes.NameToServerIdentity(rootName)
			// We don't want to store this node's identity in this slice
			if !sID.Equal(s.ServerIdentity()) {
				s.rootsIDs = append(s.rootsIDs, sID)
			}
		}
	}

	s.orderedServerIdentities = args.Roster.List
	s.treeIDSToSets = args.Translations
	s.distances = args.Distances
	return &VoidReply{}, nil
}

// GenesisTx creates and stores a genesis Tx with the specified ID (its key in the main bucket), CoinID and receiverPK.
// This will be the previousTx of the first real Tx, which needs it to pass the verification function.
// It needs to be called on every service.
func (s *Service) GenesisTx(args *GenesisArgs) (*VoidReply, error) {
	storage, err := protobuf.Encode(&TxStorage{Tx: transaction.Tx{Inner: transaction.InnerTx{ReceiverPK: args.ReceiverPK}}})
	if err != nil {
		return &VoidReply{}, err
	}
	err = s.db.Update(func(bboltTx *bbolt.Tx) error {
		// Store in the main bucket
		b := bboltTx.Bucket(s.bucketNameTx)
		err = b.Put(args.ID, storage)
		if err != nil {
			return err
		}
		// Store as last transaction in the LastTx bucket for every TreeID
		b = bboltTx.Bucket(s.bucketNameLastTx)
		for id := range s.trees {
			// Initialize the index of the atomic int, and the atomic int itself
			s.coinToAtomic[id.String()+string(args.CoinID)] = len(s.atomicCoinReserved)
			s.atomicCoinReserved = append(s.atomicCoinReserved, 0)

			// Store as last Tx
			err = b.Put(append([]byte(id.String()), args.CoinID...), args.ID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return &VoidReply{}, err
}

// HandleRaw handles SendRaw, launches TreesBLSCoSi
func (s *Service) HandleRaw(env *network.Envelope) error {
	req, ok := env.Msg.(*CoSiSendRaw)
	if !ok {
		return errors.New("Error in HandleRaw")
	}
	s.TreesBLSCoSi(&req.CoSiTrees)
	return nil
}

// TreesBLSCoSi finds the trees rooted at this node and runs the protocol on them concurrently.
// The "Message" argument is always an encoded transaction.
// It propagates the transaction and the aggregate signatures so that they're stored.
// If the Transmit argument is true, this node will contact the roots of the trees it's a part of, so that they launch
// this function themselves for the same Tx.
// The signatures returned are ordered like the corresponding trees.
func (s *Service) TreesBLSCoSi(args *CoSiTrees) (*CoSiReplyTrees, error) {
	// log.LLvl1(s.ServerIdentity())
	if args.Transmit {
		coSiTree := &CoSiTrees{
			Message: args.Message,
			// We don't want infinite loops
			Transmit: false,
		}
		// TODO: SendRaw does not work yet
		for _, ID := range s.rootsIDs {
			err := s.SendRaw(ID, &CoSiSendRaw{*coSiTree})
			log.ErrFatal(err)
		}
	}
	tx := transaction.Tx{}
	err := protobuf.DecodeWithConstructors(args.Message, &tx, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		log.ErrFatal(err)
		return nil, err
	}
	// We send the initialization on the entire roster before sending signatures
	trees := s.Lc.LocalityTrees[s.Lc.Nodes.GetServerIdentityToName(s.ServerIdentity())][1:]
	n := len(trees)
	if n == 0 {
		return nil, nil
	}
	fullTree := trees[n-1]
	data := PropagateData{Tx: tx, ServerID: s.ServerIdentity().String()}

	// Propagate over the last tree which is the "complete" one
	err = s.startPropagation(s.propagateF, fullTree, &data)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(n)
	treeIDS := make([]onet.TreeID, n)
	signatures := make([][]byte, n)
	var problem error
	for i, tree := range trees {
		err := s.vf(args.Message, tree.ID)
		if err != nil {
			return nil, err
		}
		go func(i int, tree *onet.Tree) {
			defer wg.Done()
			pi, _ := s.CreateProtocol(protoName, tree)
			pi.(*simpleblscosi.SimpleBLSCoSi).Message = args.Message
			pi.Start()
			// Send signatures one by one after the initialization
			sign := <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature

			err = pi.(*simpleblscosi.SimpleBLSCoSi).Problem
			if err != nil {
				problem = err
			} else {

				data := &PropagateData{
					ServerID:  s.ServerIdentity().String(),
					Tx:        tx,
					Signature: sign,
					TreeID:    tree.ID,
				}

				// check final signature
				err = s.checkBeforePropagation(data)
				if err != nil {
					problem = err
					return
				}

				// Only propagate to that specific tree
				err = s.startPropagation(s.propagateF, tree, data)
				if err != nil {
					problem = err
					return
				}

				treeIDS[i] = tree.ID
				signatures[i] = data.Signature
			}
		}(i, tree)
	}
	wg.Wait()

	if problem != nil {
		return &CoSiReplyTrees{
			TreeIDS:    treeIDS,
			Signatures: signatures,
			Message:    args.Message,
		}, problem
	}

	return &CoSiReplyTrees{
		TreeIDS:    treeIDS,
		Signatures: signatures,
		Message:    args.Message,
	}, nil
}

func (s *Service) checkBeforePropagation(data *PropagateData) error {
	txEncoded, err := protobuf.Encode(&data.Tx)
	if err != nil {
		log.Error(err)
	}
	sha := sha256.New()
	sha.Write(txEncoded)

	// First check that Tx is valid with the vf
	err = s.vf(txEncoded, data.TreeID)
	if err != nil {
		return err
	}

	// Then check the aggregate signature
	suite := pairing.NewSuiteBn256()
	err = bls.Verify(suite, s.trees[data.TreeID].Root.AggregatePublic(suite), txEncoded, data.Signature)
	if err != nil {
		return err
	}

	return nil
}

// propagateHandler receives a *PropagateData. It stores the transaction and its aggregate signatures in the "Tx"
// bucket, and tracks the last transaction for each coin and tree in the "LastTx" bucket.
func (s *Service) propagateHandler(msg network.Message) error {
	data := msg.(*PropagateData)
	//dist := s.distances[s.ServerIdentity().String()][data.ServerID]
	//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
	txEncoded, err := protobuf.Encode(&data.Tx)
	if err != nil {
		return err
	}
	sha := sha256.New()
	sha.Write(txEncoded)
	h := sha.Sum(nil)
	err = s.db.Update(func(bboltTx *bbolt.Tx) error {
		b := bboltTx.Bucket(s.bucketNameTx)
		v := b.Get(h)

		// Initialization : no aggregate signature sent yet. We only store Tx if not already done.
		// We don't store it as "LastTx" yet : we wait for an aggregate signature.
		if len(data.Signature) == 0 {
			if v != nil {
				// This Tx is already initialized in bbolt, we do nothing
				return nil
			}
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
		//defer s.atomicCoinReserved[string(set)+string(data.Tx.Inner.CoinID)].Unlock()
		key := data.TreeID.String() + string(data.Tx.Inner.CoinID)
		resourceIdx := s.coinToAtomic[key]
		defer atomic.CompareAndSwapInt32(&(s.atomicCoinReserved[resourceIdx]), 1, 0)

		// First check that Tx is valid with the vf
		// should pass because we also check before propagation
		err = s.vf(txEncoded, data.TreeID)
		if err != nil {
			return err
		}

		// Then check the aggregate signature
		// should pass because we also check before propagation
		suite := pairing.NewSuiteBn256()
		err = bls.Verify(suite, s.trees[data.TreeID].Root.AggregatePublic(suite), txEncoded, data.Signature)
		if err != nil {
			return err
		}

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

		// Register as LastTx for this tree
		err = b.Put(append([]byte(data.TreeID.String()), data.Tx.Inner.CoinID...), h)
		if err != nil {
			return err
		}

		// Register as LastTx for every subset of this tree's set
		/*for id := range s.trees {
			isSubset, err := s.IsSubSetOfNodes(data.TreeID, id)
			if err != nil {
				return err
			}
			if isSubset {
				sha0 := sha256.New()
				sha0.Write(s.treeIDSToSets[id])
				err = b.Put(append(sha0.Sum(nil), data.Tx.Inner.CoinID...), h)
				if err != nil {
					return err
				}
			}
		}*/
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func (s *Service) startPropagation(propagate propagate.PropagationFunc, tree *onet.Tree, msg network.Message) error {
	replies, err := propagate(tree, msg, 10*time.Second)
	if err != nil {
		return err
	}

	if replies != tree.Size() {
		log.Lvl1(s.ServerIdentity(), "Only got", replies, "out of", tree.Size())
	}

	return nil
}

// MemoryAllocated sends the bbolt memory allocated and the number of trees the node is a part of to the client.
func (s *Service) MemoryAllocated(req *MemoryRequest) (*MemoryReply, error) {
	var b int
	s.db.View(func(tx *bbolt.Tx) error {
		stats := tx.Bucket(s.bucketNameTx).Stats()
		b = stats.LeafInuse + stats.BranchInuse
		return nil
	})

	return &MemoryReply{
		BytesAllocated: b,
		//BytesAllocated: s.db.Stats().TxStats.PageAlloc,
		NbrTrees: len(s.trees),
	}, nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	s.RegisterProcessorFunc(cosiSendRawID, s.HandleRaw)
	_, err := c.ProtocolRegister(protoName, s.NewDefaultProtocol)
	if err != nil {
		return nil, err
	}

	if err := s.RegisterHandlers(s.GenesisTx, s.Setup, s.TreesBLSCoSi, s.MemoryAllocated); err != nil {
		return nil, errors.New("Couldn't register messages")
	}

	s.propagateF, s.mypi, err = propagate.NewPropagationFunc(c, "Propagate", s.propagateHandler, -1)
	if err != nil {
		return nil, err
	}
	s.trees = make(map[onet.TreeID]*onet.Tree)
	s.coinToAtomic = make(map[string]int)
	s.atomicCoinReserved = make([]int32, 0)

	db, bucketNameTx := s.GetAdditionalBucket([]byte("Tx"))
	_, bucketNameLastTx := s.GetAdditionalBucket([]byte("LastTx"))
	s.bucketNameTx = bucketNameTx
	s.bucketNameLastTx = bucketNameLastTx
	s.db = db
	return s, nil
}

// General functions, not tied to service

// CreateMatrixOfDistances takes a list of ServerIdentity and a LocalityNodes to create a map of maps where the two keys are
// the ServerIdentity as strings and the value is the distance separating the two.
func CreateMatrixOfDistances(serverIDs []*network.ServerIdentity, lcNodes gentree.LocalityNodes) map[string]map[string]float64 {
	outerMap := make(map[string]map[string]float64)
	for _, outerID := range serverIDs {
		innerMap := make(map[string]float64)
		for _, innerID := range serverIDs {
			oNode := lcNodes.GetByName(lcNodes.GetServerIdentityToName(outerID))
			iNode := lcNodes.GetByName(lcNodes.GetServerIdentityToName(innerID))
			innerMap[innerID.String()] = lcNodes.Distances[oNode][iNode]
		}
		outerMap[outerID.String()] = innerMap
	}
	return outerMap
}

// TreesToSetsOfNodes translates a Tree into an ordered slice of the nodes present in that tree.
// The bytes are the indexes of orderedSlice that are part of this tree, in increasing order.
// This means that different trees on the same set of nodes will translate to the same set.
// Example : Tree A has root orderedSlice[3] and children orderedSlice[0], orderedSlice[1].
// Tree B has root orderedSlice[1] and children orderedSlice[3], orderedSlice[0].
// Both will be translated to a same array of bytes : [byte(0), byte(1), byte(3)]
// We use arrays of bytes because they will be used in bbolt.
// It should be called once at the start, and the returned map will be one of the arguments of each service's Setup function.
func TreesToSetsOfNodes(trees []*onet.Tree, orderedSlice []*network.ServerIdentity) map[onet.TreeID][]byte {
	result := make(map[onet.TreeID][]byte)
	for _, tree := range trees {
		var set []byte
		for i, serverIdentity := range orderedSlice {
			// Check that this serverIdentity is in the tree's roster
			// If yes, append i as a byte
			for _, id := range tree.Roster.List {
				if serverIdentity.Equal(id) {
					set = append(set, byte(i))
					break
				}
			}
		}
		result[tree.ID] = set
	}
	return result
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

// TxChain creates a valid sequence of encoded transactions of length n, where the public and private keys of the first sender,
// the address of the genesis coin and the CoinID are given.
func TxChain(n int, pubK0 kyber.Point, privK0 kyber.Scalar, genesisID []byte, coinID []byte) ([][]byte, error) {
	payload := make([]byte, 500)
	for i := 0; i < 500; i++ {
		payload[i] = byte(i)
	}
	var txs [][]byte
	pubK, err := pubK0.MarshalBinary()
	if err != nil {
		return nil, err
	}
	privK := privK0
	var nextPubK []byte
	var nextPrivK kyber.Scalar
	prevTxHashed := genesisID
	suite := pairing.NewSuiteBn256()
	for i := 0; i < n; i++ {
		var npk kyber.Point
		nextPrivK, npk = bls.NewKeyPair(suite, random.New())
		nextPubK, _ = npk.MarshalBinary()
		inner := transaction.InnerTx{
			CoinID:     coinID,
			PreviousTx: prevTxHashed,
			SenderPK:   pubK,
			ReceiverPK: nextPubK,
		}
		pubK = nextPubK
		innerEncoded, _ := protobuf.Encode(&inner)
		signature, _ := bls.Sign(suite, privK, innerEncoded)
		privK = nextPrivK
		tx := transaction.Tx{
			Inner:     inner,
			Signature: signature,
			Payload:   payload,
		}
		txEncoded, _ := protobuf.Encode(&tx)
		txs = append(txs, txEncoded)
		sha := sha256.New()
		sha.Write(txEncoded)
		prevTxHashed = sha.Sum(nil)
	}
	return txs, nil
}

// TxUnrelated generates a variable number of IDs that can be used both as the main bucket keys for genesis coins as well as
// for coinIDs, and also returns as many encoded transactions each corresponding to a coin. This can be used in testing to generate
// many transactions on different coins. For more simplicity, the sender and receiver are always the same.
// A payload is also included for those transactions.
func TxUnrelated(n int, pubK kyber.Point, pvK kyber.Scalar) ([][]byte, [][]byte) {
	payload := make([]byte, 500)
	for i := 0; i < 500; i++ {
		payload[i] = byte(i)
	}
	suite := pairing.NewSuiteBn256()
	pbK, _ := pubK.MarshalBinary()
	_, pubK1 := bls.NewKeyPair(suite, random.New())
	pbK1, _ := pubK1.MarshalBinary()
	var ids [][]byte
	var txs [][]byte
	for i := 0; i < n; i++ {
		ids = append(ids, []byte(string(i)))
		inner := transaction.InnerTx{
			CoinID:     []byte(string(i)),
			PreviousTx: []byte(string(i)),
			SenderPK:   pbK,
			ReceiverPK: pbK1,
		}
		innerEncoded, _ := protobuf.Encode(&inner)
		signature, _ := bls.Sign(suite, pvK, innerEncoded)
		tx := transaction.Tx{
			Inner:     inner,
			Signature: signature,
			Payload:   payload,
		}
		txEncoded, _ := protobuf.Encode(&tx)
		txs = append(txs, txEncoded)
	}
	return ids, txs
}
