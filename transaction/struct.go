package transaction

import (
	"go.dedis.ch/onet/v3/network"
)

func init() {
	network.RegisterMessages(InnerTx{}, Tx{})
}

// InnerTx does not include the signature
type InnerTx struct {
	CoinID     []byte
	PreviousTx []byte
	SenderPK   []byte
	ReceiverPK []byte
}

// Tx includes the signature of the encoded InnerTx
type Tx struct {
	Inner     InnerTx
	Signature []byte
	Payload   []byte
}
