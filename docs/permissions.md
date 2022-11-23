# Permissions
Dirk has a permissions system that allows fine-grained control of access to Dirk's operations.

Dirk permissions have three components: the client, the account, and the operation.

## Clients
Client names are embedded in the certificate that is used to connect to Dirk.  These certificates must be issued by either the local certificate authority known to Dirk, or one of the trusted root certificate authorities.

Client names should be fully qualified (_i.e._ server.example.com rather than just server) to avoid potential confusion with multiple clients of the same name in different domains.

## Accounts
Accounts are standard `ethdo` account specifiers of the form `wallet/account`.  It is possible for either or both of `wallet` and `account` to be regular expressions.  Some examples of account specifiers are:

  - `Wallet1` would specify all accounts in "Wallet1"
  - `Wallet1/Acc.*` would specify all accounts in "Wallet1" that begin with "Acc"
  - `Test.*` would specify all accounts in all wallets that begin with "Test"
  - `.*/.*Test.*` would specify all accounts in all wallets, as long as the account contains "Test"
  - `Wallet2/.*[02468]` would specify all accounts in "Wallet2" that end in an even number

## Operations
An operation is a category of action.  The operations that Dirk supports are explained below:

### All
All is a qualifier to allow all operations.  Because this is a very broad permissions, it should only be used where the client is fully trusted.

### None
None is a qualifier to disallow all operations.  Note that all lists of permissions have an implicit "None" at the end of them _i.e._ if the operation is not explicitly allowed it is denied.

### Sign beacon attestation
Sign beacon attestation is the operation of signing a beacon attestation.

### Sign beacon proposal
Sign beacon proposal is the operation of signing a proposed beacon block.

### Sign
Sign is the generic signing operation.  Because there are no specific anti-slashing required for signing entities other than beacon attestations and proposals the data requirements for these operations are lower: only the data root and the signing domain are required.

### Access account
Access account is the operation to access the account, for example to list all accounts in a wallet or to obtain the account's public key.

### Create account
Create account is the operation to create a new account.  Accounts will follow the rules of the wallet in which they are created, for example creating an account in a hierarchical deterministic wallet will create that wallet at the next index in the wallet's path.

### Lock wallet
Lock wallet is the operation to lock a wallet.  Wallets must be unlocked before carrying out any write operations, for example creating a new account.  Note that Dirk will attempt to unlock wallets automatically if such an operation is requested, using the `unlocker` service.

### Unlock wallet
Unlock wallet is the operation to unlock a wallet.  Wallets must be unlocked before carrying out any write operations, for example creating a new account.  Note that Dirk will attempt to unlock wallets automatically if such an operation is requested, using the `unlocker` service.

### Lock account
Lock account is the operation to lock an account.  Accounts must be unlocked before carrying out any signing operations.  Note that Dirk will attempt to unlock accounts automatically if such an operation is requested, using the `unlocker` service.

### Unlock account
Unlock account is the operation to unlock an account.  Accounts must be unlocked before carrying out any signing operations.  Note that Dirk will attempt to unlock accounts automatically if such an operation is requested, using the `unlocker` service.

## Structure
Each client has a list of accounts, and each account has a list of permissions.  For example:

```
  client1.example.com:
    Wallet1/Account1: [Access account,Sign,Sign beacon proposal,Sign beacon attestation]
    Wallet1/Account2: [Access account,Sign,Sign beacon proposal,Sign beacon attestation]
  client2.example.com:
    Wallet2: [Access account,Sign,Sign beacon proposal,Sign beacon attestation]
  server.example.com:
    .*: [Access account,Create account]
```

Here, `client1.example.com` is able to server

### Implicit denial
Dirk adds an implicit denial at the end of each list of permissions, for example the permission list:

```
  [Unlock account, Unlock wallet]
```

is read by Dirk as "allow unlocking account, allow unlock wallet, _deny everything else_".  Implicit denial ensures that mis-configurations are more likely to end up in denying expected operations, rather than allowing unexpected operations.  This is important in two areas: firstly, if a new operation is introduced it is by default not allowed, and secondly if a mis-configuration does take place it is more likely to result in a safe, if non-optimal, set of permissions.

### Explicit denial
In addition to an implicit denial, it is possible to have explicit denials.  Explicit denial 

Explicit denial is configured by prepending the ~ symbol to the operation, for example the permission list:

```
  [~Voluntary exit, All]
```

is read by Dirk as "do not allow voluntary exits, allow all other operations".  Explicit denials are useful when you want your permissions to be of the form "allow all operations _except_..."
