# Development
  - add Amazon Secrets Manager (ASM) confidant
  - print command errors to stderr
  - provide clearer error message on configuration issues
  - use bytes rather than string on slashing protection import
  - provide full information on the data being signed with trace logging
  - update tracing implementation to use opentelemetry

# Version 1.1.0
  - garbage collect the slashing database on startup to reduce on-disk size
  - provide release metric in `dirk_release`
  - use internal account cache for both positive and negative caching
  - run signing rules in parallel, increasing responsiveness for large requests
  - use hierarchical log levels in configuration; details in the configuration docs

# Version 1.0.4
  - Update dependencies

# Version 1.0.2
  - Update dependencies

# Version 1.0.1
  - Do not ignore `storage-path` configuration value
  - Move `server.storage-path` to `storage-path`
  - Explicitly close database on shutdown, with delay to allow completion
  - Wrap batch account locking with a parent mutex

# Version 1.0.0
  - Mainnet release

# Version 0.9.5
  - Pre-mainnet release
  - Update slashing protection import/export format to version 5

# Version 0.9.2
  - Use go-eth2-client specified types
  - Remove go-ssz in dependencies

# Version 0.9.1
  - Ensure GRPC service shuts down on context cancel
  - Add `--version` flag to print software version

# Version 0.9.0
  - Use fastssz for calculating hash tree roots
  - Add endpoint to sign multiple attestations in a single call
  - Provide hard-coded daemon for testing (see `testing` directory)
  - Add commands to import and export slashing protection data
  - Provide additional trace logging for distributed key generation
  - Enforce requirement that peer names cannot be the same
  - Exit early in distributed key generation if execution fails
  - Allow `process.generation-passphrase` to be a Majordomo URL
  - Add comments to rules functions
  - Log location of wallet stores on startup

# Version 0.8.0
Initial public release.
