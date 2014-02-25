# Signing module

Signing module provides the way to secure key/value pairs. If one pair is registered, the module could verify whether or not the pair is invalid or modified.

What it internally does is to generate signature for data, store it in etcd, and verify whether or not the data fits the signature if called.

fleet does not yet have any custom authentication, so security of a given fleet cluster depends on a user's ability to access any host in that cluster. The suggested method of authentication is public SSH keys and ssh-agents. See the [Remote fleet access][r] for help doing this.

[r]: remote-access.md

Signing module uses the suggested way of authentication to sign and verify data. To get the signature of data, it would connect to ssh-agent, and send sign request based on the instruction in [PROTOCOL.agent][p] section 2.6.2. On the other side, to check the integrity of data, it grabs all authrorized keys in the local machine, which is at `~/.ssh/authorized_keys` by default, and verifies the correctness of the signature.

[p]: http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

# API

General APIs:
```
// Register registers the signing for key/value pair
// Recommend to use the same key/value as the one written into etcd
func (s *Signing) Register(key, value string) error

// Deregister deregisters signing for key
func (s *Signing) Deregister(key string)

// Verify verifies whether or not the pair fits its signing
func (s *Signing) Verify(key, value string) (bool, error)
```

It is currently used for job payload only.

# Storing on etcd

It creates the directory `/signing`, and stores the signature of key/value pair in `/signing/$key`.
