# Development
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
