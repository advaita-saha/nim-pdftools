# Build the test binaries optimized: the AES-256 revision-6 key derivation
# (PDF Algorithm 2.B) is deliberately expensive and crawls in a debug build.
--define:release
