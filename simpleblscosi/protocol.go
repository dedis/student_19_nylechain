package simpleblscosi

import (
	"errors"
	"sync"

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

	// Inherited from the service
	set []byte

	// Keys are concatenations of TreeID + CoinID
	mutexs map[string]*sync.Mutex

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
func NewProtocol(node *onet.TreeNodeInstance, vf VerificationFn, set []byte, mutexs map[string]*sync.Mutex,
	suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	c := &SimpleBLSCoSi{
		TreeNodeInstance: node,
		suite:            suite,
		vf:               vf,
		set:              set,
		mutexs:           mutexs,
		done:             make(chan bool),
		FinalSignature:   make(chan []byte, 1),
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
	c.Message = in.Message
	log.Lvlf3("%s prepare message: %x", c.ServerIdentity(), c.Message)

	// if we are leaf, we should go to prepare-reply
	if c.IsLeaf() {
		return c.handlePrepareReplies(nil)
	}
	// send to children
	return c.SendToChildren(in)
}

// handleAllCommitment relay the commitments up in the tree
// It expects *in* to be the full set of messages from the children.
// The children's commitment must remain constants.
func (c *SimpleBLSCoSi) handlePrepareReplies(replies []*SimplePrepareReply) error {
	log.Lvl3(c.ServerIdentity(), "aggregated")

	if err := c.vf(c.Message, c.Tree().ID); err != nil {
		return c.handleError(&TransmitError{Error: err.Error()})
	}

	// combine the signatures from the replies
	mySig, err := bls.Sign(c.suite, c.Private(), c.Message)
	if err != nil {
		log.Error(c.ServerIdentity(), err)
		return c.handleError(&TransmitError{Error: err.Error()})
	}
	sigBuf, err := bls.AggregateSignatures(c.suite, append(prepareRepliesToSigs(replies), mySig)...)
	if err != nil {
		log.Error(c.ServerIdentity(), err)
		return c.handleError(&TransmitError{Error: err.Error()})
	}

	// if we are the root, we need to start the commit phase
	if c.IsRoot() {
		out := &SimpleCommit{
			AggrSig: sigBuf,
		}
		log.Lvlf3("%s starting commit (message = %x)", c.ServerIdentity(), c.Message)
		return c.handleCommit(out)
	}

	// otherwise send it to parent
	outMsg := &SimplePrepareReply{
		Sig: sigBuf,
	}
	return c.SendTo(c.Parent(), outMsg)
}

// handleCommit dispatch the commit to the round and then dispatch the
// results down the tree.
func (c *SimpleBLSCoSi) handleCommit(in *SimpleCommit) error {
	tx := transaction.Tx{}
	err := protobuf.Decode(c.Message, &tx)
	if err != nil {
		return err
	}
	key := string(c.set) + string(tx.Inner.CoinID)
	c.mutexs[key].Lock()
	log.Lvlf3("%s handling commit", c.ServerIdentity())

	// check that the commit is correct with respect to the aggregate key
	pk := bls.AggregatePublicKeys(c.suite, c.Publics()...)
	err = bls.Verify(c.suite, pk, c.Message, in.AggrSig)
	if err != nil {
		log.Error(c.ServerIdentity(), "commit verification failed with error: ", err.Error())
		return err
	}

	// if we are leaf, then go to commitReply
	if c.IsLeaf() {
		return c.handleCommitReplies(nil)
	}

	// otherwise send it to children
	return c.SendToChildren(in)
}

// handleCommitReplies brings up the commitReply of each node in the tree to the root.
func (c *SimpleBLSCoSi) handleCommitReplies(replies []*SimpleCommitReply) error {

	if err := c.vf(c.Message, c.Tree().ID); err != nil {
		return c.handleError(&TransmitError{Error: err.Error()})
	}

	defer func() {
		// protocol is finished
		close(c.done)
		c.Done()
	}()

	log.Lvl3(c.ServerIdentity(), "aggregated")

	// combine the signatures from the replies and my own signature
	mySig, err := bls.Sign(c.suite, c.Private(), c.Message)
	if err != nil {
		return err
	}
	sigBuf, err := bls.AggregateSignatures(c.suite, append(commitRepliesToSigs(replies), mySig)...)
	if err != nil {
		return err
	}

	out := &SimpleCommitReply{
		Sig: sigBuf,
	}

	// send it back to parent
	if !c.IsRoot() {
		return c.SendTo(c.Parent(), out)
	}

	// send it to the output channel
	log.Lvl2(c.ServerIdentity(), "sending the final signature to channel")
	c.FinalSignature <- sigBuf
	return nil
}

// handleError transmits the error up the tree
func (c *SimpleBLSCoSi) handleError(tErr *TransmitError) error {
	if c.IsRoot() {
		return c.handleShutdown(&Shutdown{Error: tErr.Error})
	}
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
	key := string(c.set) + string(tx.Inner.CoinID)
	c.mutexs[key].Unlock()

	if !c.IsLeaf() {
		c.SendToChildren(shutdown)
	}
	if c.IsRoot() {
		c.FinalSignature <- nil
		c.Problem = errors.New(shutdown.Error)
	}

	return errors.New(shutdown.Error)
}

func commitRepliesToSigs(replies []*SimpleCommitReply) [][]byte {
	sigs := make([][]byte, len(replies))
	for i, reply := range replies {
		sigs[i] = reply.Sig
	}
	return sigs
}

func prepareRepliesToSigs(replies []*SimplePrepareReply) [][]byte {
	sigs := make([][]byte, len(replies))
	for i, reply := range replies {
		sigs[i] = reply.Sig
	}
	return sigs
}
