# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Known-answer tests for the hand-written crypto primitives.

import
  std/strutils,
  unittest2,
  ../src/crypto/rc4,
  ../src/crypto/aes,
  ../src/crypto/sha2

proc toHex(b: openArray[byte]): string =
  result = ""
  for x in b: result.add toHex(int(x), 2).toLowerAscii

proc bytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

suite "crypto":
  test "rc4 known-answer vectors":
    check toHex(rc4(bytes("Key"), bytes("Plaintext"))) == "bbf316e8d940af0ad3"
    check toHex(rc4(bytes("Wiki"), bytes("pedia"))) == "1021bf0420"

  test "aes-128 FIPS-197 vector":
    # encrypt one block via CBC with zero IV (single block == ECB)
    let
      pt = hexToBytes("00112233445566778899aabbccddeeff")
      k128 = hexToBytes("000102030405060708090a0b0c0d0e0f")
      zero = hexToBytes("00000000000000000000000000000000")
      ct128 = aesCbcEncryptRaw(k128, zero, pt)
    check toHex(ct128) == "69c4e0d86a7b0430d8cdb78070b4c55a"
    check toHex(aesCbcDecryptRaw(k128, zero, ct128)) ==
      "00112233445566778899aabbccddeeff"

  test "aes-256 FIPS-197 vector":
    let
      pt = hexToBytes("00112233445566778899aabbccddeeff")
      k256 = hexToBytes("000102030405060708090a0b0c0d0e0f" &
        "101112131415161718191a1b1c1d1e1f")
      zero = hexToBytes("00000000000000000000000000000000")
      ct256 = aesCbcEncryptRaw(k256, zero, pt)
    check toHex(ct256) == "8ea2b7ca516745bfeafc49904b496089"
    check toHex(aesCbcDecryptRaw(k256, zero, ct256)) ==
      "00112233445566778899aabbccddeeff"

  test "sha-2 abc and empty vectors":
    check toHex(sha256(bytes("abc"))) ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    check toHex(sha384(bytes("abc"))) ==
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" &
      "8086072ba1e7cc2358baeca134c825a7"
    check toHex(sha512(bytes("abc"))) ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    check toHex(sha256(bytes(""))) ==
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
