package simplechain

import "go.dedis.ch/onet/v3/network"

func init() {
	network.RegisterMessages(&Tx{}, &Vote{})
}

type Chain struct {
	db          DB
	unspentPool map[[32]byte]Tx
}

func (c *Chain) AddTx(tx Tx) error {
	// TODO check that what we're storing is a valid tx
	// i.e., signature is correct and it is unspent
	return c.db.StoreTx(tx)
}

func (c *Chain) AddVote(v Vote) error {
	// TODO check that the vote is correctly signed
	// TODO what do we do if there are conflicting votes, return a special error?
	return c.db.StoreVote(v)
}

func (c *Chain) GetTx(txID [32]byte) (Tx, error) {
	return c.db.GetTx(txID)
}

func (c *Chain) GetVote(ring int, txID [32]byte) (Vote, error) {
	return c.db.GetVote(ring, txID)
}
