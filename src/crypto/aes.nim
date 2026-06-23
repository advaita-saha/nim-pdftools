# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## AES block cipher (FIPS-197) in pure Nim: key sizes 128/192/256.
##
## Provides single-block encrypt/decrypt, CBC mode (encrypt + decrypt), and a
## PKCS#7 unpad helper. PDF uses AES-128-CBC (AESV2, revision 4) and
## AES-256-CBC (AESV3, revision 6); the revision-6 key-derivation step also
## needs raw AES-128-CBC encryption with no padding.

import
  std/strutils

const sbox: array[256, byte] = [
  0x63'u8,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

var rsbox: array[256, byte]
for i in 0 ..< 256:
  rsbox[int(sbox[i])] = byte(i)

const rcon: array[11, byte] = [
  0x00'u8,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

proc xtime(x: byte): byte {.inline.} =
  ## Multiply by 2 in GF(2^8).
  if (x and 0x80'u8) != 0: byte((int(x) shl 1) xor 0x1b)
  else: byte(int(x) shl 1)

proc gmul(a, b: byte): byte =
  ## Multiply two bytes in GF(2^8).
  var
    aa = a
    bb = b
    p: byte = 0
  for _ in 0 ..< 8:
    if (bb and 1'u8) != 0: p = p xor aa
    aa = xtime(aa)
    bb = bb shr 1
  p

type AesKey* = object
  rounds: int
  rk: seq[byte]  ## expanded round keys, 16*(rounds+1) bytes

proc expandKey*(key: openArray[byte]): AesKey =
  ## Expand a 16/24/32-byte key into the AES round-key schedule.
  let nk = key.len div 4
  doAssert key.len in [16, 24, 32], "AES key must be 16, 24 or 32 bytes"
  result.rounds = nk + 6
  let total = 4 * (result.rounds + 1)   # number of 4-byte words
  result.rk = newSeq[byte](total * 4)
  for i in 0 ..< key.len:
    result.rk[i] = key[i]
  var temp: array[4, byte]
  for i in nk ..< total:
    for k in 0 ..< 4:
      temp[k] = result.rk[(i - 1) * 4 + k]
    if i mod nk == 0:
      # RotWord + SubWord + Rcon
      let t0 = temp[0]
      temp[0] = sbox[int(temp[1])] xor rcon[i div nk]
      temp[1] = sbox[int(temp[2])]
      temp[2] = sbox[int(temp[3])]
      temp[3] = sbox[int(t0)]
    elif nk > 6 and i mod nk == 4:
      for k in 0 ..< 4:
        temp[k] = sbox[int(temp[k])]
    for k in 0 ..< 4:
      result.rk[i * 4 + k] = result.rk[(i - nk) * 4 + k] xor temp[k]

proc addRoundKey(state: var array[16, byte], rk: openArray[byte], round: int) =
  for i in 0 ..< 16:
    state[i] = state[i] xor rk[round * 16 + i]

proc encryptBlock(k: AesKey, inp: openArray[byte], off: int): array[16, byte] =
  var s: array[16, byte]
  for i in 0 ..< 16: s[i] = inp[off + i]
  addRoundKey(s, k.rk, 0)
  for round in 1 ..< k.rounds:
    # SubBytes
    for i in 0 ..< 16: s[i] = sbox[int(s[i])]
    # ShiftRows (state is column-major: byte r + 4c)
    var t = s
    s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1]
    s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6]
    s[3]=t[15]; s[7]=t[3]; s[11]=t[7]; s[15]=t[11]
    # MixColumns
    for c in 0 ..< 4:
      let i = c * 4
      let a0=s[i]; let a1=s[i+1]; let a2=s[i+2]; let a3=s[i+3]
      s[i]   = gmul(a0,2) xor gmul(a1,3) xor a2 xor a3
      s[i+1] = a0 xor gmul(a1,2) xor gmul(a2,3) xor a3
      s[i+2] = a0 xor a1 xor gmul(a2,2) xor gmul(a3,3)
      s[i+3] = gmul(a0,3) xor a1 xor a2 xor gmul(a3,2)
    addRoundKey(s, k.rk, round)
  # final round (no MixColumns)
  for i in 0 ..< 16: s[i] = sbox[int(s[i])]
  var t = s
  s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1]
  s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6]
  s[3]=t[15]; s[7]=t[3]; s[11]=t[7]; s[15]=t[11]
  addRoundKey(s, k.rk, k.rounds)
  s

proc decryptBlock(k: AesKey, inp: openArray[byte], off: int): array[16, byte] =
  var s: array[16, byte]
  for i in 0 ..< 16: s[i] = inp[off + i]
  addRoundKey(s, k.rk, k.rounds)
  for round in countdown(k.rounds - 1, 1):
    # InvShiftRows
    var t = s
    s[1]=t[13]; s[5]=t[1]; s[9]=t[5]; s[13]=t[9]
    s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6]
    s[3]=t[7]; s[7]=t[11]; s[11]=t[15]; s[15]=t[3]
    # InvSubBytes
    for i in 0 ..< 16: s[i] = rsbox[int(s[i])]
    addRoundKey(s, k.rk, round)
    # InvMixColumns
    for c in 0 ..< 4:
      let i = c * 4
      let a0=s[i]; let a1=s[i+1]; let a2=s[i+2]; let a3=s[i+3]
      s[i]   = gmul(a0,0x0e) xor gmul(a1,0x0b) xor gmul(a2,0x0d) xor gmul(a3,0x09)
      s[i+1] = gmul(a0,0x09) xor gmul(a1,0x0e) xor gmul(a2,0x0b) xor gmul(a3,0x0d)
      s[i+2] = gmul(a0,0x0d) xor gmul(a1,0x09) xor gmul(a2,0x0e) xor gmul(a3,0x0b)
      s[i+3] = gmul(a0,0x0b) xor gmul(a1,0x0d) xor gmul(a2,0x09) xor gmul(a3,0x0e)
  # final inverse round
  var t = s
  s[1]=t[13]; s[5]=t[1]; s[9]=t[5]; s[13]=t[9]
  s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6]
  s[3]=t[7]; s[7]=t[11]; s[11]=t[15]; s[15]=t[3]
  for i in 0 ..< 16: s[i] = rsbox[int(s[i])]
  addRoundKey(s, k.rk, 0)
  s

proc aesCbcDecryptRaw*(key, iv, data: openArray[byte]): seq[byte] =
  ## CBC decrypt without removing padding. `data.len` must be a multiple of 16.
  doAssert data.len mod 16 == 0, "AES-CBC ciphertext must be a multiple of 16"
  doAssert iv.len == 16, "AES IV must be 16 bytes"
  let k = expandKey(key)
  result = newSeq[byte](data.len)
  var prev: array[16, byte]
  for i in 0 ..< 16: prev[i] = iv[i]
  var off = 0
  while off < data.len:
    let dec = decryptBlock(k, data, off)
    for i in 0 ..< 16:
      result[off + i] = dec[i] xor prev[i]
    for i in 0 ..< 16: prev[i] = data[off + i]
    off += 16

proc aesCbcEncryptRaw*(key, iv, data: openArray[byte]): seq[byte] =
  ## CBC encrypt without adding padding. `data.len` must be a multiple of 16.
  doAssert data.len mod 16 == 0, "AES-CBC plaintext must be a multiple of 16"
  doAssert iv.len == 16, "AES IV must be 16 bytes"
  let k = expandKey(key)
  result = newSeq[byte](data.len)
  var prev: array[16, byte]
  for i in 0 ..< 16: prev[i] = iv[i]
  var
    blk: array[16, byte]
    off = 0
  while off < data.len:
    for i in 0 ..< 16: blk[i] = data[off + i] xor prev[i]
    let enc = encryptBlock(k, blk, 0)
    for i in 0 ..< 16: result[off + i] = enc[i]
    prev = enc
    off += 16

proc pkcs7Unpad*(data: seq[byte]): seq[byte] =
  ## Strip PKCS#7 padding. Returns input unchanged if padding looks invalid
  ## (some producers omit/garble it on already-block-aligned content).
  if data.len == 0 or data.len mod 16 != 0:
    return data
  let pad = int(data[^1])
  if pad < 1 or pad > 16 or pad > data.len:
    return data
  for i in 0 ..< pad:
    if int(data[data.len - 1 - i]) != pad:
      return data
  data[0 ..< data.len - pad]

proc aesCbcDecrypt*(key, iv, data: openArray[byte]): seq[byte] =
  ## CBC decrypt and remove PKCS#7 padding.
  pkcs7Unpad(aesCbcDecryptRaw(key, iv, data))

proc hexToBytes*(s: string): seq[byte] =
  ## Small helper used by tests.
  let h = s.replace(" ", "")
  result = newSeq[byte](h.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(h[2*i] & $h[2*i+1]))
