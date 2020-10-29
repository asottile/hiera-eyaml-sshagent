[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/asottile/hiera-eyaml-sshagent/master.svg)](https://results.pre-commit.ci/latest/github/asottile/hiera-eyaml-sshagent/master)

hiera-eyaml-sshagent
====================

A [hiera-eyaml] plugin which uses the ssh agent connected to `SSH_AUTH_SOCK`
to encrypt / decrypt values.

### installation

```bash
gem install hiera-eyaml-sshagent
```

### configuring

The plugin takes a single option `sshagent_keyid`:

```yaml
version: 5
hierarchy:
    -   name: "Common secret data"
        lookup_key: eyaml_lookup_key
        path: common.eyaml
        options:
          sshagent_keyid: /home/asottile/.ssh/id_rsa
    -   name: "Common data"
        path: common.yaml
```

The `keyid` should match what is printed from `ssh-add -l`

### how it works

It is based on code / ideas from the following:

- [blog post demoing ssh agent api in python][blog-post]
- [initial demo implementation in python][ssh-agent-python]
- [cryptography stackexchange: Is it safe to derive a password from a signature provided by ssh-agent?][se-is-it-safe]
- [security stackexchange: Is it possible to use SSH agent for generic data encryption?][se-ssh-agent]
- [sshcrypt]

#### retrieve symmetric key

This procedure takes a keyid, a 64 byte challenge, and a 16 byte salt.

1. list ssh identities by querying `SSH_AUTH_SOCK`
2. find the identity matching `keyid`
3. sign the `challenge` using that identity
4. use the response blob as a "password" with pbkdf2_hmac (using the salt)
5. the result is a 32 byte key which will be used with fernet

#### `encrypt(keyid, blob)`

1. generate a 64 byte "challenge" and 16 byte salt
2. retrieve symmetric key
3. encrypt with the symmetric key
4. store a blob of `{challenge, salt, payload}`

#### `decrypt(keyid, blob)`

1. load the stored blob `{challenge, salt, payload}`
2. retrieve symmetric key
3. decrypt with symmetric key

### why?

I use a [masterless puppet setup][personal-puppet] to manage my machines.

My current bootstrapping process is:

1. place ssh key on machine
2. clone the repo
3. `./run-puppet`

As such, I wanted a `hiera-eyaml` backend which didn't involve typing in more
passwords or copying around more keys (since I'm already using my ssh key).

[hiera-eyaml]: https://github.com/voxpupuli/hiera-eyaml
[blog-post]: http://ptspts.blogspot.com/2010/06/how-to-use-ssh-agent-programmatically.html
[ssh-agent-python]: https://github.com/asottile/ssh-agent-python
[se-is-it-safe]: https://crypto.stackexchange.com/q/19631/65568
[se-ssh-agent]: https://security.stackexchange.com/q/55757/197558
[sshcrypt]: https://github.com/leighmcculloch/sshcrypt
[personal-puppet]: https://github.com/asottile/personal-puppet
