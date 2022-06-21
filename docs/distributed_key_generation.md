# Distributed key generation
This document provides an example of setting up multiple Dirk instances to provide distributed key generation.

### Example
The architecture we want to build contains three Dirk instances, with any two able to provide a valid signature.

#### Setting up Dirk
(Note that this and the following assume a Unix style CLI.)

The first thing that needs to be created is somehwere for the Dirk instances to store their configuration, certificates _etc_.:

```sh
mkdir -p ${HOME}/dirk-multi/1/wallets
mkdir -p ${HOME}/dirk-multi/1/storage
mkdir -p ${HOME}/dirk-multi/1/security
mkdir -p ${HOME}/dirk-multi/2/wallets
mkdir -p ${HOME}/dirk-multi/2/storage
mkdir -p ${HOME}/dirk-multi/2/security
mkdir -p ${HOME}/dirk-multi/3/wallets
mkdir -p ${HOME}/dirk-multi/3/storage
mkdir -p ${HOME}/dirk-multi/3/security
```

The `wallets` directory of each instance needs to be populated with a wallet that can manage distributed keys:

```sh
ethdo --basedir=${HOME}/dirk-multi/1/wallets wallet create --type=distributed --wallet=DistributedWallet
ethdo --basedir=${HOME}/dirk-multi/2/wallets wallet create --type=distributed --wallet=DistributedWallet
ethdo --basedir=${HOME}/dirk-multi/3/wallets wallet create --type=distributed --wallet=DistributedWallet
```

The `security` directory of each instance needs to be populated with certificates.  Although all three instances are running on the same server they _cannot_ have the same name, hence we create three certificates (note that in a real deployment the Dirk instances should be on different servers for both security and availability purposes).  We assume that a certificate authority has already been created as per the [getting started instructions](getting_started.md#creating-certificates), so all that needs to be created is the server certificate:

```sh
SERVERNAME=$(hostname)-1
```

```sh
openssl genrsa -out ${SERVERNAME}.key 4096
```

Once the key is generated we need to create a file that contains details about the server name and the functions of the certificate.

```sh
cat >${SERVERNAME}.ext <<EOEXT
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
  
[alt_names]
DNS.1 = ${SERVERNAME}
EOEXT
```

```sh
openssl req -out ${SERVERNAME}.csr -key ${SERVERNAME}.key -new -subj "/CN=${SERVERNAME}" -addext "subjectAltName=DNS:${SERVERNAME}"
```

```sh
openssl x509 -req -in ${SERVERNAME}.csr -CA dirk_authority.crt -CAkey dirk_authority.key -CAcreateserial -out ${SERVERNAME}.crt -days 1825 -sha256 -extfile ${SERVERNAME}.ext
```

The above should be repeated for each host.  In this case our hostname is `x1`, and we have created three hosts `x1-1`, `x1-2` and `x1-3` by repeating the above commands changing `SERVERNAME` and then repeating the commmands for each.  We copy the certificate and key to each instance, and the root CA certificate to all three instances:

```sh
cp x1-1.crt x1-1.key ${HOME}/dirk-multi/1/security/
cp x1-2.crt x1-2.key ${HOME}/dirk-multi/2/security/
cp x1-3.crt x1-3.key ${HOME}/dirk-multi/3/security/
cp dirk_authority.crt ${HOME}/dirk-multi/1/security/ca.crt
cp dirk_authority.crt ${HOME}/dirk-multi/2/security/ca.crt
cp dirk_authority.crt ${HOME}/dirk-multi/3/security/ca.crt
```

> You will need to alter your `/etc/hosts` file to ensure that `hostname`-1, `hostname`-2 and `hostname`-3 resolve correctly.  For example, the /etc/hosts file for the sample server above has been changed to:
> ```
> 127.0.1.1	x1 x1-1 x1-2 x1-3
> ```

And finally we create a configuration file for each instance:

```sh
cat >${HOME}/dirk-multi/1/dirk.yml <<EOCFG
server:
  id: 1
  name: `hostname`-1
  listen-address: 0.0.0.0:8881
certificates:
  ca-cert: file://${HOME}/dirk-multi/1/security/ca.crt
  server-cert: file://${HOME}/dirk-multi/1/security/`hostname`-1.crt
  server-key: file://${HOME}/dirk-multi/1/security/`hostname`-1.key
storage-path: ${HOME}/dirk-multi/1/storage
stores:
- name: Local
  type: filesystem
  location: ${HOME}/dirk-multi/1/wallets
peers:
  1: `hostname`-1:8881
  2: `hostname`-2:8882
  3: `hostname`-3:8883
unlocker:
  account-passphrases:
    - secret
process:
  generation-passphrase: secret
permissions:
  client1: 
    DistributedWallet: All
EOCFG
```

```sh
cat >${HOME}/dirk-multi/2/dirk.yml <<EOCFG
server:
  id: 2
  name: `hostname`-2
  listen-address: 0.0.0.0:8882
certificates:
  ca-cert: file://${HOME}/dirk-multi/2/security/ca.crt
  server-cert: file://${HOME}/dirk-multi/2/security/`hostname`-2.crt
  server-key: file://${HOME}/dirk-multi/2/security/`hostname`-2.key
storage-path: ${HOME}/dirk-multi/2/storage
stores:
- name: Local
  type: filesystem
  location: ${HOME}/dirk-multi/2/wallets
peers:
  1: `hostname`-1:8881
  2: `hostname`-2:8882
  3: `hostname`-3:8883
unlocker:
  account-passphrases:
    - secret
process:
  generation-passphrase: secret
permissions:
  client1: 
    DistributedWallet: All
EOCFG
```

```sh
cat >${HOME}/dirk-multi/3/dirk.yml <<EOCFG
server:
  id: 3
  name: `hostname`-3
  listen-address: 0.0.0.0:8883
certificates:
  ca-cert: file://${HOME}/dirk-multi/3/security/ca.crt
  server-cert: file://${HOME}/dirk-multi/3/security/`hostname`-3.crt
  server-key: file://${HOME}/dirk-multi/3/security/`hostname`-3.key
storage-path: ${HOME}/dirk-multi/3/storage
stores:
- name: Local
  type: filesystem
  location: ${HOME}/dirk-multi/3/wallets
peers:
  1: `hostname`-1:8881
  2: `hostname`-2:8882
  3: `hostname`-3:8883
process:
  generation-passphrase: secret
unlocker:
  account-passphrases:
    - secret
permissions:
  client1: 
    DistributedWallet: All
EOCFG
```

There are a few items in the configuration file above that may be new.  The `stores` block contains a list of wallets for which Dirk provides key management, the `process` block contains a secret that is used when encrypting generated keys in `generation-passphrase`, and the `unlocker` block contains secrets that allow automatic unlocking of the encrypted keys.  In a real deployment it would be expected that these values would be long random strings, different for each instance and stored remotely, for maximum security.

At this point it should be possible to start Dirk.  In three separate windows run the commands:

```sh
dirk --base-dir=${HOME}/dirk-multi/1
```

```sh
dirk --base-dir=${HOME}/dirk-multi/2
```

```sh
dirk --base-dir=${HOME}/dirk-multi/3
```

Each should provide output that states "All services operational", at which point Dirk should be ready.

### Creating a distributed account
We use `ethdo` to create a distributed account.  As explained in the [getting started guide](getting_started.md), `ethdo` interacts with the dirk using additional options:

  -  `--remote` the address of the Dirk instance
  - `--client-cert` and `--client-key` the path to the certificate and keyfile for the client
  - `--ca-cert` the path to the certificate for the server authority

Assuming the certificates are in a directory `security` in your home directory, you can create a distributed account with:

```sh
ethdo account create \
  --remote=`hostname`-1:8881 \
  --server-ca-cert ${HOME}/security/ca.crt \
  --client-cert ${HOME}/security/client1.crt \
  --client-key ${HOME}/security/client1.key \
  --account=DistributedWallet/1 \
  --signing-threshold=2 \
  --participants=3
```

Assuming this returns without error you can confirm that the account exists:

```sh
ethdo account info \
  --remote=`hostname`-1:8881 \
  --server-ca-cert ${HOME}/security/ca.crt \
  --client-cert ${HOME}/security/client1.crt \
  --client-key ${HOME}/security/client1.key \
  --account=DistributedWallet/1 \
  --verbose
```

which should give output like:

```
Public key: 0x80119c7c42026df27af4888f79bf8a4d7b8d0490f5de2f6f0d76fab3dcf9cb7ab1210ee261eb91c6abba65e3407e8f8e
Composite public key: 0x8f225302f9e8a0408090c90ad73bf21bec95f806f3168a6ea5b5c915f592fd64031f5b5c96cf4bd163a10db3fe8ab7e6
Signing threshold: 2/3
```

Note that the same composite public key and signing threshold should be obtained from each of the three instances, although the component public keys will be different:

```sh
ethdo account info \
  --remote=`hostname`-2:8882 \
  --server-ca-cert ${HOME}/security/ca.crt \
  --client-cert ${HOME}/security/client1.crt \
  --client-key ${HOME}/security/client1.key \
  --account=DistributedWallet/1 \
  --verbose
```

which should give output like:

```sh
Public key: 0x83be9fc753d6a27168882f298caa2bff8f070d122d373fa7582328a86e65a800b2dd165f4311dd573dc806f5a1561d87
Composite public key: 0x8f225302f9e8a0408090c90ad73bf21bec95f806f3168a6ea5b5c915f592fd64031f5b5c96cf4bd163a10db3fe8ab7e6
Signing threshold: 2/3
```

```sh
ethdo account info \
  --remote=`hostname`-3:8883 \
  --server-ca-cert ${HOME}/security/ca.crt \
  --client-cert ${HOME}/security/client1.crt \
  --client-key ${HOME}/security/client1.key \
  --account=DistributedWallet/1 \
  --verbose
```

which should give output like:

```
Public key: 0x874f8f3318be3bdf33f0268915ffce5865e1a87eb70a1d86e349af0b07b88c52706ea8cdc41d41c770f0bf5ab273f1f2
Composite public key: 0x8f225302f9e8a0408090c90ad73bf21bec95f806f3168a6ea5b5c915f592fd64031f5b5c96cf4bd163a10db3fe8ab7e6
Signing threshold: 2/3
```

### Signing
Signing will usually be carried out programatically, however for the purposes of testing it is possible to use `ethdo` to request signatures:

```sh
ethdo signature sign \
  --remote=`hostname`-1:8881 \
  --server-ca-cert ${HOME}/security/ca.crt \
  --client-cert ${HOME}/security/client1.crt \
  --client-key ${HOME}/security/client1.key \
  --account=DistributedWallet/1 \
  --data=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  --domain=0xf000000000000000000000000000000000000000000000000000000000000000
  --verbose
```

which should give output like:

```
0x8864060c1a2467c24d1cadd6fc1e9d99a65c9566208ecebbd0699bb10fb6655534a1678f3842eeecc4655551b60bd5e51098b9b2e9c1974e4f33b866fa209a644358a676fe3faa268fcbd8791b9817099f566876833c683117364379aa26b665
```

Note that it is possible to use any of the Dirk instances as the `remote`.  It is also possible to shut down any one of the Dirk instances and the above command will still complete (changing `remote` as required so that it does not point to the downed instance, of course).
