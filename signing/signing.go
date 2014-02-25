package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/user"
	"path/filepath"
	"strings"

	gossh "github.com/coreos/fleet/third_party/code.google.com/p/go.crypto/ssh"

	"github.com/coreos/fleet/registry"
	"github.com/coreos/fleet/ssh"
)

const (
	DefaultAuthorizedKeyFile = "~/.ssh/authorized_keys"
)

type Signing struct {
	registry          *registry.Registry
	// keyring is used to sign data, created when needed
	keyring gossh.ClientKeyring
	// keys is used to verify signing, created when needed
	pubkeys []gossh.PublicKey
}

// New returns a new Signing variable
func New(registry *registry.Registry) *Signing {
	return &Signing{registry, nil, nil}
}

// SetSignBySSHAgent sets using ssh-agent to sign
func (s *Signing) SetSignBySSHAgent() error {
	var err error
	if s.keyring, err = ssh.NewSSHAgentKeyring(); err != nil {
		return err
	}
	return nil
}

// SetSignBySSHAgent sets using ssh-agent to verify
func (s *Signing) SetVerifyBySSHAgent() error {
	keyring, err := ssh.NewSSHAgentKeyring()
	if err != nil {
		return err
	}

	pubkeys := make([]gossh.PublicKey, 0)
	for i := 0; ; i++ {
		pubkey, err := keyring.Key(i)
		if err == ssh.ErrKeyOutofIndex {
			break
		}
		if err != nil {
			return err
		}
		pubkeys = append(pubkeys, pubkey)
	}
	s.pubkeys = pubkeys

	return nil
}

// SetSignBySSHAgent sets using authorized key file to verify
func (s *Signing) SetVerifyByAuthroziedKeyFile(filepath string) error {
	filepath, err := parseFilepath(filepath)
	if err != nil {
		return err
	}

	if s.pubkeys, err = loadAuthorizedKeys(filepath); err != nil {
		return err
	}
	return nil
}

// Register registers the signing for key/value pair
// Recommend to use the same key/value as the one written into etcd
func (s *Signing) Register(key, value string) error {
	signs, err := s.sign(valueForSign(key, value))
	if err != nil {
		return err
	}

	return s.registry.CreateSignature(key, signs)
}

// Deregister deregisters signing for key
func (s *Signing) Deregister(key string) {
	s.registry.DestroySignature(key)
}

// Verify verifies whether or not the pair fits its signing
func (s *Signing) Verify(key, value string) (bool, error) {
	signs := s.registry.GetSignature(key)

	return s.verify(valueForSign(key, value), signs)
}

func (s *Signing) sign(data []byte) ([][]byte, error) {
	if s.keyring == nil {
		return nil, errors.New("sign method is unset")
	}

	sigs := make([][]byte, 0)
	// Generate all possible signatures
	for i := 0; ; i++ {
		sig, err := s.keyring.Sign(i, nil, data)
		if err == ssh.ErrKeyOutofIndex {
			break
		}
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}
	return sigs, nil
}

func (s *Signing) verify(data []byte, signs [][]byte) (bool, error) {
	if s.pubkeys == nil {
		return false, errors.New("verify method is unset")
	}

	// Enumerate all pairs to verify signatures
	for _, authKey := range s.pubkeys {
		for _, sign := range signs {
			if authKey.Verify(data, sign) {
				return true, nil
			}
		}
	}

	return false, nil
}

// use the concatenation of key and value to protect both
func valueForSign(key, value string) []byte {
	return []byte(key + value)
}

// get absolute file path considering user home directory
func parseFilepath(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	path = strings.Replace(path, "~", usr.HomeDir, 1)

	return filepath.Abs(path)
}

func loadAuthorizedKeys(filepath string) ([]gossh.PublicKey, error) {
	out, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	pubkeys := make([]gossh.PublicKey, 0)
	for len(out) > 0 {
		pubkey, _, _, rest, ok := gossh.ParseAuthorizedKey(out)
		if !ok {
			return nil, errors.New("fail to parse authorized key file")
		}
		out = rest

		pubkeys = append(pubkeys, pubkey)
	}

	return pubkeys, nil
}

func marshal(obj interface{}) (string, error) {
	encoded, err := json.Marshal(obj)
	if err == nil {
		return string(encoded), nil
	} else {
		return "", errors.New(fmt.Sprintf("Unable to JSON-serialize object: %s", err))
	}
}
