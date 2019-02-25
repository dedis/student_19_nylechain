package nylechain

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"sync"
	"time"

	"go.dedis.ch/cothority/v3/messaging"

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
	network.RegisterMessage(&storage{})
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	propagateF messaging.PropagationFunc

	storage *storage
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("main")

// storage is used to save our data.
type storage struct {
	Signature chan []byte
	sync.Mutex
}

// SimpleBLSCoSi starts a simpleblscosi-protocol and returns the final signature.
// The client chooses the message to be signed.
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
	signature := &CoSiReply{
		Signature: <-pi.(*simpleblscosi.SimpleBLSCoSi).FinalSignature,
	}
	s.startPropagation(s.propagateF, cosi.Roster, signature)
	return signature, nil
}
func (s *Service) propagateHandler(msg network.Message) error {
	s.storage.Signature <- msg.([]byte)
	return nil
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

// saves all data.
func (s *Service) save() {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.storage = &storage{}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return errors.New("Data of wrong type")
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
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}

	var err error
	s.propagateF, err = messaging.NewPropagationFunc(c, "Propagate", s.propagateHandler, -1)
	if err != nil {
		return nil, err
	}
	return s, nil
}
