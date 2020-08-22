# dirk

[![Tag](https://img.shields.io/github/tag/attestantio/dirk.svg)](https://github.com/attestantio/dirk/releases/)
[![License](https://img.shields.io/github/license/attestantio/dirk.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/attestantio/dirk?status.svg)](https://godoc.org/github.com/attestantio/dirk)
[![Travis CI](https://img.shields.io/travis/attestantio/dirk.svg)](https://travis-ci.org/attestantio/dirk)
[![codecov.io](https://img.shields.io/codecov/c/github/attestantio/dirk.svg)](https://codecov.io/github/attestantio/dirk)
[![Go Report Card](https://goreportcard.com/badge/github.com/attestantio/dirk)](https://goreportcard.com/report/github.com/attestantio/dirk)

An Ethereum 2 distributed remote keymanager.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

`dirk` is a standard Go module which can be installed with:

```sh
go get github.com/attestantio/dirk
```

## Usage

`dirk` provides an interface to wallet operations such as listing accounts and signing requests.  The daemon provides a number of security measures to avoid unauthorised uses of the private keys, and protection against invalid actions (_e.g._ slashing events).

## Architecture

### Configuration directory and files

By default `dirk` looks for its configuration in the file `.dirk.json` in the user's home directory.  A different base directory for `dirk` can be given with the `--base-dir` flag, in which case it will look for a file `dirk.json` in that directory.

### Example

The architecture we want to achieve is shown below:

![Validator architecture](images/architecture.png)

In this architecture we have three validators clients.  Validator clients 1 and 2 are in a cluster, and between them manage accounts 1, 2, and 3.  Validator client 3 is standalone, and manages account 4.

#### Creating wallets and accounts
The first step is to create some wallets and validator keys for said wallets, using [ethdo](https://github.com/wealdtech/ethdo):

```
$ ethdo wallet create --wallet=wallet1
$ ethdo account create --account=wallet1/account1 --passphrase=secret
$ ethdo account create --account=wallet1/account2 --passphrase=secret
$ ethdo account create --account=wallet1/account3 --passphrase=secret
$ ethdo wallet create --wallet=wallet2
$ ethdo account create --account=wallet2/account4 --passphrase=secret
```

Here we have two wallets, one for each set of validator clients.  It is possible for different wallets to have different features, such as level of security and location, but for the purposes of this example they are both standard (non-deterministic) wallets (see ethdo documentation for other options).

#### Creating certificates
We need a certificate for the wallet daemon.  We could use a certificate from a well-known certificate authority such as LetsEncrypt, or we could create our own; we will create our own using [certstrap](https://github.com/square/certstrap).

First, we create the certificate authority.  Note the key created in this process is critical to the security of your deposits and should be protected with all reasonable measures; this should include a passphrase when promted.
```
$ certstrap --depot-path . init --common-name "dirk authority" --expires "3 years"
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Created ./dirk_authority.key (encrypted by passphrase)
Created ./dirk_authority.crt
Created ./dirk_authority.crl
```

The server needs its own certificate.  We use the sample name `server.example.com` here but you should replace this with the name of your server.  If you are testing `dirk` locally you can use `localhost` instead of the server name.
```
$ certstrap --depot-path . request-cert --common-name server.example.com
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Created ./server.example.com.key
Created ./server.example.com.csr
$ certstrap --depot-path . sign --CA "dirk authority" --expires="3 years" server.example.com
Enter passphrase for CA key (empty for no passphrase): 
Created ./server.example.com.crt from ./server.example.com.csr signed by ./dirk_authority.key
```

Next, we create and sign certificates for the three clients that will be connecting to the daemon.  Note the keys created here should not have a passphrase supplied; they will reside with the valdiator clients so use of the key is should be possible without requiring human intervention (to allow for server restarts _etc._).  For the first client:

```
$ certstrap --depot-path . request-cert --common-name client1
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Created ./client1.key
Created ./client1.csr
$ certstrap --depot-path . sign --CA "dirk authority" --expires="3 years" client1
Enter passphrase for CA key (empty for no passphrase): 
Created ./client1.crt from ./client1.csr signed by ./dirk_authority.key
```

and the same commands can be used for the other clients, using "client2" and "client3" in place of "client1".  At this point you should have the following files:

  - `client1.crt`: the signed certificate for client1; needs to be moved to the server running client1
  - `client1.csr`: the signing request for client1; can be deleted
  - `client1.key`: the key for client1; needs to be moved to the server running client1
  - `client2.crt`: the signed certificate for client2; needs to be moved to the server running client3
  - `client2.csr`: the signing request for client2; can be deleted
  - `client2.key`: the key for client2; needs to be moved to the server running client3
  - `client3.crt`: the signed certificate for client3; needs to be moved to the server running client3
  - `client3.csr`: the signing request for client3; can be deleted
  - `client3.key`: the key for client3; needs to be moved to the server running client3
  - `server.example.com.crt`: the certificate for `dirk`; needs to be moved to the server running `dirk`
  - `server.example.com.csr`: the signing request for `dirk`; can be deleted
  - `server.example.com.key`: the key for `dirk`; needs to be moved to the server running `dirk`
  - `dirk_authority.crl`: the certificate revocation list for dirk; needs to be copied to the server running `dirk`
  - `dirk_authority.crt`: the certificate for dirk; needs to be copied to all clients
  - `dirk_authority.key`: the key for dirk; needs to be copied to the server running `dirk`

To provide the certificates for `dirk` make a directory `dirk/security` in your home directory and copy the `server.example.com.crt` and `server.example.com.key` files in to it.  Also copy `dirk_authority.crt` to the same directory with the name `ca.crt`.  The contents of the `security` directory in your configuration directory should be:

  - `ca.crt`: copy of `dirk_authority.crt` from the previous step
  - `server.example.com.crt`: copy of `server.example.com.crt` from the previous step
  - `server.example.com.key`: copy of `server.example.com.key` from the previous step

At this point you also need a minimal configuration file so `dirk` knows which certificates to use.  Create a file `dirk.json` in your home directory with the following contents:

```json
{
  "server": {
    "id": 212483780,
    "name": "server.example.com",
    "listen-address": "localhost:9091",
    "cert-path": "security"
  }
}
```

(The `id` and `listen-address` fields here will be explained later).

You can confirm the configuration of the certificates by running the command `dirk --show-certificates` which should return suitable information about the generated certificates:

```sh
$ dirk --show-certificates
Server certificate issued by: Dirk authority
Server certificate expires: 2023-03-24 13:47:19 +0000 UTC
Server certificate issued to: server.example.com

Certificate authority certificate is: Dirk authority
Certificate authority certificate expires: 2023-03-24 13:47:20 +0000 UTC
```

#### Adding permissions
The next step is to configure `dirk` to know which clients have access to which accounts, and which operations on those accounts.  To do so, replace the `dirk.json` file above with the following:

```
{
  "server": {
    "id": 212483780,
    "name": "server.example.com",
    "listen-address": "localhost:9091",
    "cert-path": "security"
  },
  "permissions": {
    "client1": {
      "wallet1": "All"
    },
    "client2": {
      "wallet1": "All"
    },
    "client3": {
      "wallet2": "All"
    }
  }
}
```

Once this is in place it can be confirmed by running `dirk --show-permissions`:

```
$ dirk --show-permissions
Permissions for "client1":
 - accounts matching the path "wallet1" can carry out all operations
Permissions for "client2":
 - accounts matching the path "wallet1" can carry out all operations
Permissions for "client3":
 - accounts matching the path "wallet2" can carry out all operations
```

Permissions can be used to restrict the access of clients to wallets, accounts, and operations.  More details can be found in ther permissions documentation.

#### Starting `dirk`

To start `dirk` type:

```sh
$ dirk
{"level":"info","version":"v0.1.0","time":"2020-07-27T23:20:51+01:00","message":"Starting dirk"}
{"level":"warn","time":"2020-07-27T23:20:51+01:00","message":"No stores configured; using default"}
{"level":"info","service":"api","impl":"grpc","address":"localhost:9091","time":"2020-07-27T23:20:51+01:00","message":"Listening"}
{"level":"info","time":"2020-07-27T23:20:51+01:00","message":"All services operational"}
```

At this point `dirk` is operational on port 9091 and can accept requests for key generation, signing _etc._

#### Testing client permissions
`ethdo` interacts with the dirk using additional options:
  -  `--remote` the address of the Dirk instance
  - `--client-cert` and `--client-key` the path to the certificate and keyfile for the client
  - `--ca-cert` the path to the certificate for the server authority

For example, to list accounts accessible in `wallet1` with the `client1` certificate:

```sh
$ ethdo --remote=server.example.com:9091 --client-cert=client1.crt --client-key=client1.key --server-ca-cert=dirk_authority.crt wallet accounts --wallet=wallet1
account1
account3
account2
```

As would be expected from the configured permissions, `client3` cannot access the accounts in `wallet1`:

```sh
$ ethdo --remote=server.example.com:9091 --client-cert=client3.crt --client-key=client3.key --server-ca-cert=Wallet_daemon_authority.crt wallet accounts --wallet=wallet1
```

At this point it has been confirmed that the client permissions operate as expected, and that dirk is appropriately configured.  The client certificates can now be used by validators to remotely access their keys.

## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/attestantio/dirk/issues).

## License

[Apache-2.0](LICENSE) © 2020 Attestant Limited.
