package domain

import (
	"encoding/json"
	"time"
)

type OAuth struct {
	User        string    `json:"user"`
	Email       string    `json:"email"`
	Team        string    `json:"team"`
	EmailDomain string    `json:"email_domain"`
	Domain      string    `json:"domain"`
	Created     time.Time `json:"created"`
}

func (o *OAuth) Key() string {
	return o.Created.Format(time.RFC3339) + "|" + o.Team
}

// Bytify return a json []byte that is not indented
func Bytify(in interface{}) []byte {
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	return b
}

// Stringify return a json string that is not indented
func Stringify(in interface{}) string {
	return string(Bytify(in))
}
