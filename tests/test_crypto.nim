# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Known-answer tests for the hand-written crypto primitives.

import
  std/strutils,
  ../src/crypto/rc4,
  ../src/crypto/aes,
  ../src/crypto/sha2

proc toHex(b: openArray[byte]): string =
  result = ""
  for x in b: result.add toHex(int(x), 2).toLowerAscii

proc bytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

var failures = 0
proc check(name, got, want: string) =
  if got == want:
    echo "ok   ", name
  else:
    inc failures
    echo "FAIL ", name, "\n  got  ", got, "\n  want ", want

# --- RC4 (classic test vector) ---
check "rc4 Key/Plaintext",
  toHex(rc4(bytes("Key"), bytes("Plaintext"))), "bbf316e8d940af0ad3"
check "rc4 Wiki/pedia",
  toHex(rc4(bytes("Wiki"), bytes("pedia"))), "1021bf0420"

# --- AES (FIPS-197 vectors) ---
block:
  let
    pt = hexToBytes("00112233445566778899aabbccddeeff")
    k128 = hexToBytes("000102030405060708090a0b0c0d0e0f")
  # encrypt one block via CBC with zero IV (single block == ECB)
  let
    zero = hexToBytes("00000000000000000000000000000000")
    ct128 = aesCbcEncryptRaw(k128, zero, pt)
  check "aes-128 encrypt", toHex(ct128), "69c4e0d86a7b0430d8cdb78070b4c55a"
  check "aes-128 decrypt", toHex(aesCbcDecryptRaw(k128, zero, ct128)),
    "00112233445566778899aabbccddeeff"
  let
    k256 = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ct256 = aesCbcEncryptRaw(k256, zero, pt)
  check "aes-256 encrypt", toHex(ct256), "8ea2b7ca516745bfeafc49904b496089"
  check "aes-256 decrypt", toHex(aesCbcDecryptRaw(k256, zero, ct256)),
    "00112233445566778899aabbccddeeff"

# --- SHA-2 ("abc") ---
check "sha256 abc", toHex(sha256(bytes("abc"))),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
check "sha384 abc", toHex(sha384(bytes("abc"))),
  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" &
  "8086072ba1e7cc2358baeca134c825a7"
check "sha512 abc", toHex(sha512(bytes("abc"))),
  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
check "sha256 empty", toHex(sha256(bytes(""))),
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

if failures == 0:
  echo "\nALL CRYPTO TESTS PASSED"
else:
  echo "\n", failures, " FAILURES"
  quit(1)
