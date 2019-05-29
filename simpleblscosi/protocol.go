package simpleblscosi

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/dedis/student_19_nylechain/transaction"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// SimpleBLSCoSi is the main structure holding the round and the onet.Node.
type SimpleBLSCoSi struct {
	suite *pairing.SuiteBn256
	*onet.TreeNodeInstance
	// the message we want to sign typically given by the Root
	Message []byte
	// the verification to run during upon receiving the prepare message
	vf VerificationFn

	commitMsg SimpleCommit

	// Inherited from the service
	treeID onet.TreeID

	// Keys are concatenations of TreeID + CoinID
	coinToAtomic       map[string]int
	atomicCoinReserved []int32

	// Distances between servers
	distances map[string]map[string]float64

	prepare      chan prepareChan
	prepareReply chan prepareReplyChan
	commit       chan commitChan
	commitReply  chan commitReplyChan
	err          chan errorChan
	shutdown     chan shutdownChan
	done         chan bool

	// FinalSignature is the channel that the root should listen on to get the final signature
	FinalSignature chan []byte

	// Problem is a non-nil error if the transaction was refused
	Problem error
}

// VerificationFn is a verification functions
type VerificationFn func(msg []byte, id onet.TreeID) error

// NewProtocol is a callback that is executed when starting the protocol.
func NewProtocol(node *onet.TreeNodeInstance, vf VerificationFn, treeID onet.TreeID, atomicCoinReserved []int32,
	coinToAtomic map[string]int, distances map[string]map[string]float64, suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	c := &SimpleBLSCoSi{
		TreeNodeInstance:   node,
		suite:              suite,
		vf:                 vf,
		treeID:             treeID,
		coinToAtomic:       coinToAtomic,
		atomicCoinReserved: atomicCoinReserved,
		distances:          distances,
		done:               make(chan bool),
		FinalSignature:     make(chan []byte, 1),
	}

	// Register the channels we want to register and listens on
	err := node.RegisterChannels(&c.prepare, &c.prepareReply, &c.commit, &c.commitReply, &c.err, &c.shutdown)
	return c, err
}

// Dispatch will listen on the four channels we use (i.e. four steps)
func (c *SimpleBLSCoSi) Dispatch() error {
	nbrChild := len(c.Children())
	if !c.IsRoot() {
		log.Lvl3(c.ServerIdentity(), "waiting for prepare")
		prep := (<-c.prepare).SimplePrepare
		err := c.handlePrepare(&prep)
		if err != nil {
			return err
		}
	}
	if !c.IsLeaf() {
		var buf []*SimplePrepareReply

		for i := 0; i < nbrChild; i++ {
			select {
			case reply := <-c.prepareReply:
				log.Lvlf3("%s collecting prepare replies %d/%d", c.ServerIdentity(), i, nbrChild)
				buf = append(buf, &reply.SimplePrepareReply)
			case err := <-c.err:
				c.handleError(&err.TransmitError)
				if !c.IsRoot() {
					shutdown := (<-c.shutdown).Shutdown
					c.handleShutdown(&shutdown)
				}
				<-c.done
				return nil
			}
		}
		err := c.handlePrepareReplies(buf)
		if err != nil {
			return err
		}
	}
	if !c.IsRoot() {
		log.Lvl3(c.ServerIdentity(), "waiting for commit")
		select {
		case commit := <-c.commit:
			err := c.handleCommit(&commit.SimpleCommit)
			if err != nil {
				return err
			}
		case err := <-c.err:
			c.handleError(&err.TransmitError)
			if !c.IsRoot() {
				shutdown := (<-c.shutdown).Shutdown
				c.handleShutdown(&shutdown)
			}
			<-c.done
			return nil
		case shutdown := <-c.shutdown:
			c.handleShutdown(&shutdown.Shutdown)
			<-c.done
			return nil
		}
	}
	if !c.IsLeaf() {
		var buf []*SimpleCommitReply
		for i := 0; i < nbrChild; i++ {
			commitReply := <-c.commitReply
			log.Lvlf3("%s handling commitReply of child %d/%d", c.ServerIdentity(), i, nbrChild)
			buf = append(buf, &commitReply.SimpleCommitReply)
		}
		err := c.handleCommitReplies(buf)
		if err != nil {
			return err
		}
	}
	<-c.done
	return nil
}

// Start will call the announcement function of its inner Round structure. It
// will pass nil as *in* message.
func (c *SimpleBLSCoSi) Start() error {
	out := &SimplePrepare{c.Message}
	return c.handlePrepare(out)
}

// handlePrepare will pass the message to the round and send back the
// output. If in == nil, we are root and we start the round.
func (c *SimpleBLSCoSi) handlePrepare(in *SimplePrepare) error {
	var err error

	c.Message = in.Message
	log.Lvlf3("%s prepare message: %x", c.ServerIdentity(), c.Message)

	// if we are leaf, we should go to prepare-reply
	if c.IsLeaf() {
		return c.handlePrepareReplies(nil)
	}

	// send to children
	var wg sync.WaitGroup
	wg.Add(len(c.Children()))
	for _, child := range c.Children() {
		go func(child *onet.TreeNode) {
			defer wg.Done()
			//dist := c.distances[c.ServerIdentity().String()][child.ServerIdentity.String()]
			//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
			err0 := c.SendTo(child, in)
			if err != nil {
				err = err0
			}
		}(child)

	}
	return err
}

// handlePrepareReplies verifies the transaction, emits a corresponding positive
// or negative reply, signs it and aggregates it to the corresponding set of replies from children
// It expects *in* to be the full set of messages from the children.
// The children's commitment must remain constants.
func (c *SimpleBLSCoSi) handlePrepareReplies(replies []*SimplePrepareReply) error {
	log.Lvl3(c.ServerIdentity(), "aggregated")

	// verify that txn signed by sender, last txn in the coin and holder is sender
	if err := c.vf(c.Message, c.Tree().ID); err != nil {
		return c.handleError(&TransmitError{Error: err.Error()})
	}

	// sign the transaction
	mySig, err := bls.Sign(c.suite, c.Private(), c.Message)
	if err != nil {
		log.Error(c.ServerIdentity(), err)
		return c.handleError(&TransmitError{Error: err.Error()})
	}

	// reserve the resource
	tx := transaction.Tx{}
	err = protobuf.Decode(c.Message, &tx)
	if err != nil {
		return err
	}
	key := c.treeID.String() + string(tx.Inner.CoinID)
	resourceIdx := c.coinToAtomic[key]
	succeeded := atomic.CompareAndSwapInt32(&(c.atomicCoinReserved[resourceIdx]), 0, 1)

	var posAggrSig, negAggrSig []byte
	if !succeeded {
		// resource occupied, send negative answer
		log.Lvl3(c.ServerIdentity(), "sending to parent negative for", tx.Inner.ReceiverPK)
		sigs := prepareRepliesToSigs(replies, false)
		if len(sigs) > 0 {
			negAggrSig, err = bls.AggregateSignatures(c.suite, append(sigs, mySig)...)
			if err != nil {
				log.Error(c.ServerIdentity(), err)
				return c.handleError(&TransmitError{Error: err.Error()})
			}
		} else {
			negAggrSig = mySig
		}

		posAggrSig, err = bls.AggregateSignatures(c.suite, prepareRepliesToSigs(replies, true)...)
		if err != nil {
			return err
		}
	} else {
		log.Lvl3(c.ServerIdentity(), "sending to parent positive for", tx.Inner.ReceiverPK)
		sigs := prepareRepliesToSigs(replies, true)
		if len(sigs) > 0 {
			posAggrSig, err = bls.AggregateSignatures(c.suite, append(sigs, mySig)...)
			if err != nil {
				log.Error(c.ServerIdentity(), err)
				return c.handleError(&TransmitError{Error: err.Error()})
			}
		} else {
			posAggrSig = mySig
		}

		negAggrSig, err = bls.AggregateSignatures(c.suite, prepareRepliesToSigs(replies, false)...)
		if err != nil {
			return err
		}
	}

	// combine the signatures from the replies

	// if we are the root, we need to start the commit phase
	if c.IsRoot() {
		out := &SimpleCommit{
			NegAggrSig: negAggrSig,
			PosAggrSig: posAggrSig,
		}

		log.Lvlf3("%s starting commit (message = %x)", c.ServerIdentity(), c.Message)
		return c.handleCommit(out)
	}

	// otherwise send it to parent

	outMsg := &SimplePrepareReply{
		NegSig: negAggrSig,
		PosSig: posAggrSig,
	}

	//dist := c.distances[c.ServerIdentity().String()][c.Parent().ServerIdentity.String()]
	//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
	log.Lvlf3("%s sending to parent", c.ServerIdentity())
	return c.SendTo(c.Parent(), outMsg)
}

// handleCommit dispatch the commit to the round and then dispatch the
// results down the tree.
func (c *SimpleBLSCoSi) handleCommit(in *SimpleCommit) error {

	var err error
	c.commitMsg = *in

	log.Lvlf3("%s handling commit", c.ServerIdentity())

	// if we are leaf, then go to commitReply
	if c.IsLeaf() {
		return c.handleCommitReplies(nil)
	}

	// otherwise send it to children
	var wg sync.WaitGroup
	wg.Add(len(c.Children()))
	for _, child := range c.Children() {
		go func(child *onet.TreeNode) {
			defer wg.Done()
			//dist := c.distances[c.ServerIdentity().String()][child.ServerIdentity.String()]
			//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
			err0 := c.SendTo(child, in)
			if err != nil {
				err = err0
			}
		}(child)

	}
	return err
}

// handleCommitReplies brings up the commitReply of each node in the tree to the root.
func (c *SimpleBLSCoSi) handleCommitReplies(replies []*SimpleCommitReply) error {

	defer func() {
		// protocol is finished
		close(c.done)
		c.Done()
	}()

	tx := transaction.Tx{}
	err := protobuf.Decode(c.Message, &tx)
	if err != nil {
		return err
	}

	// TODO check that I signed the coming prepare, use a mask
	/*
		if err := c.vf(c.Message, c.Tree().ID); err != nil {
			return c.handleError(&TransmitError{Error: err.Error()})
		}
	*/

	var posAggrSig, negAggrSig []byte

	mySig, err := bls.Sign(c.suite, c.Private(), c.Message)
	if err != nil {
		return err
	}

	// the optimistic case:
	// check that the positive commit is correct with respect to the aggregate key
	pk := bls.AggregatePublicKeys(c.suite, c.Publics()...)
	err = bls.Verify(c.suite, pk, c.Message, c.commitMsg.PosAggrSig)
	if err != nil {
		log.Error(c.ServerIdentity(), "positive commit verification failed with error: ", err.Error(), "for", tx.Inner.ReceiverPK)

		// TODO: handle the cases when the nr of positive sign + nr of negative sigs isn't 2f+1

		// emit a negative commit
		// combine the signatures from the replies and my own signature
		sigs := commitRepliesToSigs(replies, false)

		if len(sigs) > 0 {
			negAggrSig, err = bls.AggregateSignatures(c.suite, append(sigs, mySig)...)
			if err != nil {
				return err
			}

		} else {
			negAggrSig = mySig

		}

		posAggrSig, err = bls.AggregateSignatures(c.suite, commitRepliesToSigs(replies, true)...)
		if err != nil {
			return err
		}

	} else {
		// emit a positive commit
		// combine the signatures from the replies and my own signature
		sigs := commitRepliesToSigs(replies, true)
		if len(sigs) > 0 {
			posAggrSig, err = bls.AggregateSignatures(c.suite, append(sigs, mySig)...)
			if err != nil {
				return err
			}
		} else {
			posAggrSig = mySig
		}

		negAggrSig, err = bls.AggregateSignatures(c.suite, commitRepliesToSigs(replies, false)...)
		if err != nil {
			return err
		}

	}

	log.Lvl3(c.ServerIdentity(), "aggregated")

	out := &SimpleCommitReply{
		PosSig: posAggrSig,
		NegSig: negAggrSig,
	}

	// send it back to parent
	if !c.IsRoot() {
		//dist := c.distances[c.ServerIdentity().String()][c.Parent().ServerIdentity.String()]
		//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
		return c.SendTo(c.Parent(), out)
	}

	// send it to the output channel
	log.Lvl3(c.ServerIdentity(), "sending the final signature to channel")
	c.FinalSignature <- posAggrSig
	return nil
}

// handleError transmits the error up the tree
func (c *SimpleBLSCoSi) handleError(tErr *TransmitError) error {
	if c.IsRoot() {
		return c.handleShutdown(&Shutdown{Error: tErr.Error})
	}
	//dist := c.distances[c.ServerIdentity().String()][c.Parent().ServerIdentity.String()]
	//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
	return c.SendTo(c.Parent(), &TransmitError{Error: tErr.Error})
}

// handleShutdown unlocks and shuts down every node down the tree
func (c *SimpleBLSCoSi) handleShutdown(shutdown *Shutdown) error {
	defer func() {
		// protocol is finished
		close(c.done)
		c.Done()
	}()

	tx := transaction.Tx{}
	err := protobuf.Decode(c.Message, &tx)
	if err != nil {
		return err
	}

	/*
		key := string(c.set) + string(tx.Inner.CoinID)
		c.atomicCoinReserved[key].Unlock()
	*/

	key := c.treeID.String() + string(tx.Inner.CoinID)
	resourceIdx := c.coinToAtomic[key]
	atomic.CompareAndSwapInt32(&(c.atomicCoinReserved[resourceIdx]), 1, 0)

	if !c.IsLeaf() {
		var wg sync.WaitGroup
		wg.Add(len(c.Children()))
		for _, child := range c.Children() {
			go func(child *onet.TreeNode) {
				defer wg.Done()
				//dist := c.distances[c.ServerIdentity().String()][child.ServerIdentity.String()]
				//time.Sleep(time.Duration(dist) / 10 * time.Millisecond)
				err0 := c.SendTo(child, shutdown)
				if err != nil {
					err = err0
				}
			}(child)
		}
		wg.Wait()
		return err
	}
	if c.IsRoot() {
		c.FinalSignature <- nil
		c.Problem = errors.New(shutdown.Error)
	}

	return errors.New(shutdown.Error)
}

func commitRepliesToSigs(replies []*SimpleCommitReply, usePosReplies bool) [][]byte {
	sigs := make([][]byte, 0)
	for _, reply := range replies {
		if usePosReplies {
			if len(reply.PosSig) > 0 {
				sigs = append(sigs, reply.PosSig)
			}
		} else {
			if len(reply.NegSig) > 0 {
				sigs = append(sigs, reply.NegSig)
			}
		}
	}
	return sigs
}

func prepareRepliesToSigs(replies []*SimplePrepareReply, usePosReplies bool) [][]byte {
	sigs := make([][]byte, 0)
	for _, reply := range replies {
		if usePosReplies {
			if len(reply.PosSig) > 0 {
				sigs = append(sigs, reply.PosSig)
			}
		} else {
			if len(reply.NegSig) > 0 {
				sigs = append(sigs, reply.NegSig)
			}
		}
	}
	//log.LLvl1("len is", len(sigs))
	return sigs
}
