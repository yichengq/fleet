# Signing module

Signing module provides the way to secure values stored in etcd service. It can generate signature for data, store it in etcd, and verify whether or not the data has been modified.

fleet does not yet have any custom authentication, so security of a given fleet cluster depends on a user's ability to access any host in that cluster. The suggested method of authentication is public SSH keys and ssh-agents. See the [Remote fleet access][r] for help doing this.

[r]: remote-access.md

Signing module uses the suggested way of authentication to sign and verify data. To get the signature of data, it would connect to ssh-agent, and send sign request based on the instruction in [PROTOCOL.agent][p] section 2.6.2. On the other side, to check the integrity of data, it grabs all authrorized keys in the local machine, which is at `~/.ssh/authorized_keys` by default, and verifies the correctness of the signature.

[p]: http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

# API

```
// CreateSigning creates signing for key/value pair on etcd
func (r *Registry) CreateSigning(key, value string) error

// DestroySigning deletes signing for key from etcd
func (r *Registry) DestroySigning(key string)

// VerifySigning verifies whether or not value fits its signing
func (r *Registry) VerifySigning(key, value string) (bool, error)
```

It is currently used for job payload only. And it could be used to sign on other datata in the future.

# Storing on etcd

It creates the directory `/signing` under fleet directory, and stores the signature of key/value pair in the same relative path under `/signing`.
