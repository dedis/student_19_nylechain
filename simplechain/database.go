package simplechain

import (
	"errors"
	"sync"
)

type DB interface {
	// GetTx gets the transaction.
	GetTx([32]byte) (Tx, error)
	// GetVote gets the vote.
	GetVote(int, [32]byte) (Vote, error)
	// StoreTx stores the transaction.
	StoreTx(Tx) error
	// StoreVote stores the vote.
	StoreVote(Vote) error
}

func NewMemoryDB() MemoryDB {
	return MemoryDB{
		txs: make(map[[32]byte]Tx),
		// we shouldn't have more than 100 rings hopefully, but can be
		// changed later
		votes: make([]map[[32]byte]Vote, 100),
	}
}

type MemoryDB struct {
	sync.RWMutex
	txs   map[[32]byte]Tx
	votes []map[[32]byte]Vote
}

func (db *MemoryDB) GetTx(key [32]byte) (Tx, error) {
	db.RLock()
	defer db.RUnlock()
	if tx, ok := db.txs[key]; ok {
		return tx, nil
	}
	return Tx{}, errors.New("tx does not exist")
}

func (db *MemoryDB) GetVote(ring int, key [32]byte) (Vote, error) {
	db.RLock()
	defer db.RUnlock()
	if len(db.votes) < ring || db.votes[ring] == nil {
		return Vote{}, errors.New("no such ring")
	}
	if vote, ok := db.votes[ring][key]; ok {
		return vote, nil
	}
	return Vote{}, errors.New("vote does not exist")
}

func (db *MemoryDB) StoreTx(tx Tx) error {
	db.Lock()
	defer db.Unlock()
	// do not allow overwrite
	if _, ok := db.txs[tx.Hash()]; ok {
		return errors.New("tx already exists")
	}
	db.txs[tx.Hash()] = tx
	return nil
}

func (db *MemoryDB) StoreVote(v Vote) error {
	db.Lock()
	defer db.Unlock()
	if db.votes[v.Ring] == nil {
		db.votes[v.Ring] = make(map[[32]byte]Vote)
	}
	// do not allow overwrite
	if _, ok := db.votes[v.Ring][v.TxID]; ok {
		return errors.New("vote already exists")
	}
	db.votes[v.Ring][v.TxID] = v
	return nil
}
