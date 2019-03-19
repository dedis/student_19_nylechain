package simplechain

// Vote represents a vote casted by a validator.
type Vote struct {
	Vote bool
	TxID [32]byte
	Ring int
	Sig  []byte
}

// CheckSignature does what it says.
func (v Vote) CheckSignature(pk []byte) error {
	// TODO do the actual check
	return nil
}
