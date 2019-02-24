package nylechain

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"sync"

	"github.com/dedis/student_19_nylechain/simpleblscosi"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Used for tests
var serviceID onet.ServiceID

const protoName = "simpleBLSCoSi"

func init() {
	if _, err := onet.GlobalProtocolRegister(protoName, simpleblscosi.NewDefaultProtocol); err != nil {
		log.ErrFatal(err)
	}
	var err error
	serviceID, err = onet.RegisterNewService("SimpleBLSCoSi", newService)
	log.ErrFatal(err)
	network.RegisterMessage(&storage{})
}

// Service structure
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

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
func (s *Service) SimpleBLSCoSi(roster *onet.Roster, msg []byte) ([]byte, error) {
	tree := roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, errors.New("couldn't create tree")
	}
	pi, err := s.CreateProtocol(protoName, tree)
	if err != nil {
		return nil, err
	}
	var root *simpleblscosi.SimpleBLSCoSi
	root = pi.(*simpleblscosi.SimpleBLSCoSi)
	root.Message = msg
	root.Start()
	signature := <-root.FinalSignature
	return signature, nil
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
	if err := s.RegisterHandlers(s.SimpleBLSCoSi); err != nil {
		return nil, errors.New("Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
