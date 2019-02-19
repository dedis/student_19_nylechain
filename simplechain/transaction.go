package simplechain

import (
	"crypto/sha256"
	"encoding/binary"
)

type Tx struct {
	PreviousRing int
	SpendingRing int
	SrcToken     [32]byte
	DstToken     [32]byte
	BackLink     [32]byte
}

func (tx Tx) Hash() [32]byte {
	h := sha256.New()

	i1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(i1, uint32(tx.PreviousRing))
	h.Write(i1)

	i2 := make([]byte, 4)
	binary.LittleEndian.PutUint32(i2, uint32(tx.SpendingRing))
	h.Write(i2)

	h.Write(tx.SrcToken[:])
	h.Write(tx.DstToken[:])
	h.Write(tx.BackLink[:])

	sum := [32]byte{}
	copy(sum[:], h.Sum(nil))
	return sum
}
