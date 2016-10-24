package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"time"

	"encoding/json"
	"github.com/boltdb/bolt"
	"github.com/demisto/demistobot/domain"
)

const (
	HistoryBucket = "History"
)

type Repo struct {
	db *bolt.DB
}

func New(path string) (repo *Repo, err error) {
	err = os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return nil, err
	}
	repo = &Repo{}
	repo.db, err = bolt.Open(path, 0600, &bolt.Options{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	err = repo.init()
	return repo, err
}

func (r *Repo) init() error {
	return r.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(HistoryBucket))
		return err
	})
}

func (r *Repo) SaveOAuth(o *domain.OAuth) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(HistoryBucket))
		return b.Put([]byte(o.Key()), domain.Bytify(o))
	})
}

func (r *Repo) OAuths(from, to time.Time) (oauths []domain.OAuth, err error) {
	err = r.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(HistoryBucket))
		c := b.Cursor()
		// Iterate over the range
		for k, v := c.Seek([]byte(from.Format(time.RFC3339))); k != nil && (to.IsZero() || bytes.Compare(k, []byte(to.Format(time.RFC3339))) <= 0); k, v = c.Next() {
			var o domain.OAuth
			err := json.Unmarshal(v, &o)
			if err != nil {
				return err
			}
			oauths = append(oauths, o)
		}
		return nil
	})
	return
}

func (r *Repo) Close() error {
	return r.db.Close()
}
