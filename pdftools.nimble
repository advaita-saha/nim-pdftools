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
# Intentionally NONE beyond the compiler: everything (RC4, AES, SHA-2, DEFLATE
# inflate, PDF parsing) is implemented on top of the Nim standard library only.

requires "nim >= 2.0.0"

task test, "Run the test suite":
  exec "nim c -r --outdir:build tests/test_crypto.nim"
  exec "nim c -r --outdir:build tests/test_pdf.nim"
