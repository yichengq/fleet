package signing

import (
	"path"

	"github.com/coreos/fleet/job"
)

const (
	payloadPrefix = "/payload/"
)

// RegisterPayload registers the signing for payload
func (s *Signing) RegisterPayload(jp *job.JobPayload) error {
	key := path.Join(payloadPrefix, jp.Name)
	value, _ := marshal(jp)
	return s.Register(key, value)
}

// Deregister deregisters signing for payload
func (s *Signing) DeregisterPayload(name string) {
	key := path.Join(payloadPrefix, name)
	s.Deregister(key)
}

// Verify verifies whether or not the payload fits its signing
func (s *Signing) VerifyPayload(jp *job.JobPayload) (bool, error) {
	key := path.Join(payloadPrefix, jp.Name)
	value, _ := marshal(jp)
	return s.Verify(key, value)
}
