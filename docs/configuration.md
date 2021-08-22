# Configuration
Dirk can be configured through environment, command-line or configuration file.  In the case of conflicting configuration the order of precedence is:

  - command-line; then
  - environment; then
  - configuration file.

# The configuration file
Dirk's configuration file can be written in JSON or YAML.  The file can either be in the user's home directory, in which case it will be called `.dirk.json` (or `.dirk.yml`), or it can be in a directory specified by the command line option `--base-dir` or environment variable `DIRK_BASE_DIR`, in which case it will be called `dirk.json` (or `dirk.yml`).

A sample configuration file in YAML with all current options is shown below:

```
# log-file is the location for Dirk log output.  If this is not provided logs will be written to the console.
log-file: /home/me/dirk.log
# log-level is the global log level for Dirk logging.
log-level: Debug
# log-levels contain override log levels for individual modules.  A full list of modules is supplied later
# in this document.
log-levels:
  signer: Trace
  accountmanager: None
server:
  # id should be randomly chosen 8-digit numeric ID; it must be unique across all of your Dirk instances.
  id: 75843236
  # name is the name of your server, as specified in its SSL certificate.
  name: myserver.example.com
  # listen-address is the interface and port on which Dirk will listen for requests; change `127.0.0.1`
  # to `0.0.0.0` to listen on all network interfaces.
  listen-address: 127.0.0.1:13141
  rules:
    # admin-ips is a list of IP addresses from which requests for voluntary exists will be accepted.
    admin-ips: [ 1.2.3.4, 5.6.7.8 ]
certificates:
  # server-cert is the majordomo URL to the server's certificate.
  server-cert: file:///home/me/dirk/security/certificates/myserver.example.com.crt
  # server-key is the majordomo URL to the server's key.
  server-key: file:///home/me/dirk/security/certificates/myserver.example.com.key
  # ca-cert is the certificate of the CA that issued the client certificates.  If not present Dirk will use
  # the standard CA certificates supplied with the server.
  ca-cert: file:///home/me/dirk/security/certificates/ca.crt
# storage-path is the path where information created by the slashing protection system is stored.  If not
# supplied it will default to using the 'storage' directory in the user's home directory.
storage-path: /home/me/dirk/protection
# stores is a list of locations and types of Ethereum 2 stores.  If no stores are supplied Dirk will use the
# default filesystem store.
stores:
- name: Local
  type: filesystem
  location: /home/me/dirk/wallets
metrics:
  # listen-address is where Dirk's Prometheus server will present.  If this value is not present then Dirk
  # will not gather metrics.
  listen-address: localhost:8181
# tracing-address is where Dirk's tracing information will be sent. If this value is not present then Dirk will
# not generate tracing information.
tracing-address: address: metrics-server:12345
peers:
  # These are the IDs and addresses of the peers with which Dirk can communicate for distributed key generation.
  # At a minimum it must include this instance.
  75843236: myserver.example.com:13141
unlocker:
  # wallet-passphrases is a list of passphrases that can be used to unlock wallets.  Each entry is a majordomo URL.
  wallet-passphrases:
  - file:///home/me/dirk/security/passphrases/wallet-passphrase.txt
  # account-passphrases is a list of passphrases that can be used to unlock wallets.  Each entry is a majordomo URL.
  account-passphrases:
  - file:///home/me/dirk/security/passphrases/account-passphrase.txt
  - file:///home/me/dirk/security/passphrases/account-passphrase-2.txt
process:
  # generation-passphrase is the passphrase used to encrypt newly-generated accounts.  It is a majordomo URL.
  generation-passphrase: file:///home/me/dirk/security/passphrases/account-passphrase.txt
permissions:
  # This permission allows client1 the ability to carry out all operations on accounts in wallet1.
  client1:
    wallet1: All
  # This permission allows client2 the ability to carry out all operations on accounts in wallet1.
  client2:
    wallet1: All
  # This permission allows client3 the ability to carry out all operations on accounts in wallet2.
  client3:
    wallet2: All
```

## Logging
Dirk has a modular logging system that allows different modules to log at different levels.  The available log levels are:

  - **Fatal**: messages that result in Dirk stopping immediately;
  - **Error**: messages due to Dirk being unable to fulfil a valid process;
  - **Warning**: messages that result in Dirk not completing a process due to transient or user issues;
  - **Information**: messages that are part of Dirk's normal startup and shutdown process;
  - **Debug**: messages when one of Dirk's processes diverge from normal operations;
  - **Trace**: messages that detail the flow of Dirk's normal operations; or
  - **None**: no messages are written.

### Global level
The global level is used for all modules that do not have an explicit log level.  This can be configured using the command line option `--log-level`, the environment variable `DIRK_LOG_LEVEL` or the configuration option `log-level`.

### Module levels
Modules levels are used for each module, overriding the global log level.  The available modules are:

  - **accountmanager** operations on accounts such as locking and unlocking existing accounts, and generating new accounts
  - **api** operations from the external API
  - **checker** checks client access to operations
  - **fetcher** fetches wallets and accounts from Ethereum 2 stores
  - **lister** lists accounts that match a given path specification
  - **locker** locks accounts across Dirk, ensuring only a single operation can take place at a time on any given account
  - **majordomo** fetches secrets from local and remote stores
  - **metrics** provides metrics to monitor performance and operation of modules
  - **peers** provides lists of peers for distributed key generation
  - **process** carries out the distributed key generation process
  - **ruler** checks requests against slashing protection rules
  - **sender** sends data to other Dirk instances during distributed key generation
  - **signer** signs data using keys held by Dirk
  - **unlocker** unlocks locked accounts using supplied passphrases
  - **walletmanager** operations on accounts such as locking and unlocking existing wallets

This can be configured using the environment variables `DIRK_LOG_LEVELS_<MODULE>` or the configuration option `log-levels.<module>`.  For example, the peers module logging could be configured using the environment variable `DIRK_LOG_LEVELS_PEERS` or the configuration option `log-levels.peers`.
