# Permissions
Dirk has a permissions system that allows fine-grained control of access to Dirk's operations.

## Operations

### All
All is a qualifier to allow all operations.  Because this is a very broad permisisons, it should only be used where the client is fully trusted.

### None
None is a qualifier to disallow all operations.  Note that all lists of permissions have an implicit "None" at the end of them _i.e._ if the operation is not explicitly allowed it is denied.

### Sign beacon attestation
Sign beacon attestation is the operation of signing a beacon attestation.

### Sign beacon proposal
Sign beacon proposal is the operation of signing a proposed beacon block.

### Sign
Sign is the generic signing operation.  Because there are no specific anti-slashing required for signing entities other than beacon attestations and proposals the data requirements for these operations are lower: only the data root and the signing domain are required.

### Access account
      // ActionAccessAccount is the action of accessing an account.
### Create account
      // ActionCreateAccount is the action of creating an account.
### Lock wallet
      // ActionLockWallet is the action of locking a wallet.
### Unlock wallet
      // ActionUnlockWallet is the action of unlocking a wallet.
### Lock account
      // ActionLockAccount is the action of locking an account.
### Unlock account
      // ActionUnlockAccount is the action of unlocking an account.

### All

### All

## Explicit denial
In addition to an implicit denial, where none of the rules match the operation, it is possible to have explicit denials.  Explicit denials are useful when you want to say things like "allow all operations _except_..."

Explicit denial is configured by prepending the ~ symbol to the operation, for example permissions of:

```
  ~Voluntary exit, All
```

read as:
  - do not allow voluntary exits
  - allow all other operations


