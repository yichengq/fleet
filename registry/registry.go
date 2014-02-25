package registry

import (
	"encoding/json"
	"errors"
	"fmt"

	gossh "github.com/coreos/fleet/third_party/code.google.com/p/go.crypto/ssh"

	"github.com/coreos/fleet/third_party/github.com/coreos/go-etcd/etcd"
)

const (
	keyPrefix = "/_coreos.com/fleet/"
)

type Registry struct {
	etcd *etcd.Client
	// keyring is used to sign data, created when needed
	keyring gossh.ClientKeyring
	// authKeys is used to verify signing, created when needed
	authKeys []gossh.PublicKey
}

func New(client *etcd.Client) (registry *Registry) {
	return &Registry{client, nil, nil}
}

func marshal(obj interface{}) (string, error) {
	encoded, err := json.Marshal(obj)
	if err == nil {
		return string(encoded), nil
	} else {
		return "", errors.New(fmt.Sprintf("Unable to JSON-serialize object: %s", err))
	}
}

func unmarshal(val string, obj interface{}) error {
	err := json.Unmarshal([]byte(val), &obj)
	if err == nil {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Unable to JSON-deserialize object: %s", err))
	}
}
