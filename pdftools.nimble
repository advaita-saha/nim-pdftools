# pdftools — Pure-Nim CLI to decrypt (unlock) password-protected PDFs
# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

# Package

version       = "0.1.0"
author        = "Advaita Saha"
description   = "Pure-Nim CLI to decrypt (unlock) password-protected PDFs"
license       = "MIT"
srcDir        = "src"
binDir        = "build"
bin           = @["pdftools"]

# Dependencies
# The implementation itself pulls in NOTHING beyond the compiler: RC4, AES,
# SHA-2, DEFLATE inflate and PDF parsing are all built on the Nim standard
# library only.

requires "nim >= 2.0.0"

# unittest2 is the sole *testing* dependency. Scoping it to the `test` task keeps
# it out of the package's runtime dependencies, so `nimble install` never pulls
# it. Nimble drives the built-in test runner (it discovers tests/t*.nim), which
# injects the task-dependency path into the compile — a bare `nim c` would not.
# `-d:release` for the tests lives in tests/config.nims.
taskRequires "test", "unittest2"
