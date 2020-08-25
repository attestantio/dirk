# Prometheus metrics
Dirk provides a number of metrics to check the health and performance of its activities.  Dirk's default implementation uses Prometheus to provide these metrics.  The metrics server listens on the address provided by the `metrics.address` configuration value.

## Health
Health metrics provide a mechanism to confirm if Dirk is active and able to serve requests.

  - `dirk_start_time_secs` is the Unix timestamp at which Dirk was started.  This value will remain the same throughout a run of Dirk; if it increments it implies that Dirk has restarted.
  - `dirk_ready` is a flag stating if Dirk is ready to serve requests.  This value is 1 if Dirk is ready to serve requests, otherwise 0.

## Operations
Operations metrics provide information about the number of operations taking place within Dirk.

`dirk_signer_process_requests_total` number of signer processes run.  This has two labels:
  - `request` is the type of signing request, and has three possible values:
    - `proposal` is for beacon block proposals;
    - `attestation` is for beacon block attestations; or
    - `generic` is for generic signers.
  - `result` is the result of the signing process, and has three possible values:
    - `succeeded` is for requests that completed successfully;
    - `denied` is for requests that were denied by permissions, anti-slashing rules, invalid parameters _etc._; or
    - `failed` is for requests that failed to complete due to an problem with Dirk.

`dirk_account_manager_process_requests_total` number of account manager processes run.  This has two labels:
  - `request` is the type of account manager request, and has three possible values:
    - `lock` is for locking accounts;
    - `unlock` is for unlocking accounts;
    - `generate` is for generating new accounts.
  - `result` is the result of the account manager process, and has three possible values:
    - `succeeded` is for requests that completed successfully;
    - `denied` is for requests that were denied by permissions, anti-slashing rules, invalid parameters _etc._; or
    - `failed` is for requests that failed to complete due to an problem with Dirk.

`dirk_wallet_manager_process_requests_total` number of wallet manager processes run.  This has two labels:
  - `request` is the type of wallet manager request, and has two possible values:
    - `lock` is for locking wallets; or
    - `unlock` is for unlocking wallets.
  - `result` is the result of the wallet manager process, and has three possible values:
    - `succeeded` is for requests that completed successfully;
    - `denied` is for requests that were denied by permissions, anti-slashing rules, invalid parameters _etc._; or
    - `failed` is for requests that failed to complete due to an problem with Dirk.

`dirk_lister_process_requests_total` number of account lister processes run.  This has one label:
  - `result` is the result of the signing process, and has three possible values:
    - `succeeded` is for requests that completed successfully;
    - `denied` is for requests that were denied by permissions, anti-slashing rules, invalid parameters _etc._; or
    - `failed` is for requests that failed to complete due to an problem with Dirk.

## Performance
Performance metrics provide a mechanism to understand how quickly Dirk is carrying out its activities.  The following information is provided:
  
`dirk_signer_process_duration_seconds` time taken to carry out the signer process.  This has one label:
  - `request` is the type of signing request, and has three possible values:
    - `proposal` is for beacon block proposals;
    - `attestation` is for beacon block attestations; or
    - `generic` is for generic signers.

`dirk_account_manager_process_duration_seconds` time taken to carry out the account manager process.  This has one label:
  - `request` is the type of account manager request, and has three possible values:
    - `lock` is for locking accounts;
    - `unlock` is for unlocking accounts;
    - `generate` is for generating new accounts.

`dirk_wallet_manager_process_duration_seconds` time taken to carry out the wallet manager process.  This has one label:
  - `request` is the type of wallet manager request, and has three possible values:
    - `lock` is for locking wallets;
    - `unlock` is for unlocking wallets;

`dirk_lister_process_duration_seconds` time taken to carry out the account lister process.  This has one label:

These metrics are provided as histograms, with buckets in increments of 0.01 seconds up to 0.2 seconds.
