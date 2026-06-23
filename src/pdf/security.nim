# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## PDF Standard Security Handler: password-based key derivation and per-object
## decryption for revisions 2-4 (RC4 / AES-128) and revision 6 (AES-256).

{.push warning[Deprecated]: off.}
import std/md5            # stdlib MD5; used deliberately to avoid any dependency
{.pop.}
import
  std/tables,
  ./objects,
  ../crypto/rc4,
  ../crypto/aes,
  ../crypto/sha2

type
  CryptMethod* = enum cmIdentity, cmRC4, cmAESV2, cmAESV3
  SecHandler* = object
    v*, r*, keyLen*: int               ## keyLen in bytes
    fileKey*: seq[byte]
    stmMethod*, strMethod*: CryptMethod
    encryptMetadata*: bool
    usedOwnerPassword*: bool

  SecError* = object of CatchableError

const padding: array[32, byte] = [
  0x28'u8,0xbf,0x4e,0x5e,0x4e,0x75,0x8a,0x41,0x64,0x00,0x4e,0x56,0xff,0xfa,0x01,0x08,
  0x2e,0x2e,0x00,0xb6,0xd0,0x68,0x3e,0x80,0x2f,0x0c,0xa9,0xfe,0x64,0x53,0x69,0x7a]

proc md5b(data: openArray[byte]): seq[byte] =
  var c: MD5Context
  md5Init(c)
  md5Update(c, data)
  var dig: MD5Digest
  md5Final(c, dig)
  result = newSeq[byte](16)
  for i in 0 ..< 16: result[i] = dig[i]

proc strBytes(o: PdfObj): seq[byte] =
  if o != nil and o.kind == pkStr: o.s else: @[]

proc intVal(o: PdfObj, default = 0): int =
  if o != nil and o.kind == pkInt: int(o.i) else: default

# ---------------------------------------------------------------------------
# Revision 2-4 key derivation (Algorithm 2)
# ---------------------------------------------------------------------------

proc padPassword(pw: seq[byte]): seq[byte] =
  result = newSeq[byte](32)
  let n = min(pw.len, 32)
  for i in 0 ..< n: result[i] = pw[i]
  for i in n ..< 32: result[i] = padding[i - n]

proc fileKeyFromPadded(padded, o, id0: seq[byte]; p: int; r, keyLen: int;
                       encryptMetadata: bool): seq[byte] =
  var buf: seq[byte]
  buf.add padded
  for i in 0 ..< 32:
    buf.add (if i < o.len: o[i] else: 0'u8)
  let pu = uint32(p)
  buf.add byte(pu and 0xff)
  buf.add byte((pu shr 8) and 0xff)
  buf.add byte((pu shr 16) and 0xff)
  buf.add byte((pu shr 24) and 0xff)
  buf.add id0
  if r >= 4 and not encryptMetadata:
    buf.add [0xff'u8, 0xff, 0xff, 0xff]
  var digest = md5b(buf)
  if r >= 3:
    for _ in 0 ..< 50:
      digest = md5b(digest[0 ..< keyLen])
  digest[0 ..< keyLen]

proc computeU(fileKey, id0: seq[byte], r: int): seq[byte] =
  ## Algorithm 4 (R2) / 5 (R3-4): the expected /U value for this key.
  if r == 2:
    return rc4(fileKey, padding)
  var buf: seq[byte]
  buf.add padding
  buf.add id0
  var x = rc4(fileKey, md5b(buf))
  for i in 1 .. 19:
    var k = newSeq[byte](fileKey.len)
    for j in 0 ..< fileKey.len: k[j] = fileKey[j] xor byte(i)
    x = rc4(k, x)
  x   # 16 bytes; compared against U[0..15]

proc userPaddedFromOwner(ownerPw, o: seq[byte]; r, keyLen: int): seq[byte] =
  ## Algorithm 7: recover the padded user password from /O using the owner pw.
  var digest = md5b(padPassword(ownerPw))
  if r >= 3:
    for _ in 0 ..< 50:
      digest = md5b(digest[0 ..< 16])
  let rc4key = digest[0 ..< keyLen]
  if r == 2:
    return rc4(rc4key, o)
  var x = o
  for i in countdown(19, 0):
    var k = newSeq[byte](rc4key.len)
    for j in 0 ..< rc4key.len: k[j] = rc4key[j] xor byte(i)
    x = rc4(k, x)
  x

# ---------------------------------------------------------------------------
# Revision 6 key derivation (AES-256, PDF 2.0)
# ---------------------------------------------------------------------------

proc hash2B(pwd, salt, udata: seq[byte]): seq[byte] =
  ## Algorithm 2.B hardened hash used by revision 6.
  var
    input = pwd & salt & udata
    k = sha256(input)
    round = 0
  while true:
    var k1block = pwd & k & udata
    var k1 = newSeqOfCap[byte](k1block.len * 64)
    for _ in 0 ..< 64: k1.add k1block
    let e = aesCbcEncryptRaw(k[0 ..< 16], k[16 ..< 32], k1)
    var s = 0
    for i in 0 ..< 16: s += int(e[i])
    case s mod 3
    of 0: k = sha256(e)
    of 1: k = sha384(e)
    else: k = sha512(e)
    inc round
    if round >= 64 and int(e[^1]) <= round - 32:
      break
  k[0 ..< 32]

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

proc resolveMethod(cf: PdfObj, name: string): CryptMethod =
  if name == "Identity" or name == "":
    return cmIdentity
  if cf != nil and cf.kind == pkDict and cf.d.hasKey(name):
    let cfm = dictGet(cf.d[name], "CFM")
    if cfm != nil and cfm.kind == pkName:
      case cfm.name
      of "V2": return cmRC4
      of "AESV2": return cmAESV2
      of "AESV3": return cmAESV3
      of "Identity": return cmIdentity
      else: discard
  cmRC4

proc setupSecurity*(enc: PdfObj, id0: seq[byte], password: string): SecHandler =
  ## Build a handler for `enc` (the /Encrypt dictionary) using `password`.
  ## Raises SecError on an unsupported handler or a wrong password.
  let filt = dictGet(enc, "Filter")
  if filt == nil or filt.kind != pkName or filt.name != "Standard":
    raise newException(SecError,
      "unsupported security handler (only the Standard password handler is supported)")
  result.v = intVal(dictGet(enc, "V"), 0)
  result.r = intVal(dictGet(enc, "R"), 0)
  let length = intVal(dictGet(enc, "Length"), 40)
  result.keyLen = length div 8
  if result.v <= 1: result.keyLen = 5
  let
    o = strBytes(dictGet(enc, "O"))
    u = strBytes(dictGet(enc, "U"))
    p = intVal(dictGet(enc, "P"), 0)
    em = dictGet(enc, "EncryptMetadata")
  result.encryptMetadata = not (em != nil and em.kind == pkBool and em.b == false)

  if result.v >= 4:
    let
      cf = dictGet(enc, "CF")
      stmf = dictGet(enc, "StmF")
      strf = dictGet(enc, "StrF")
    result.stmMethod = resolveMethod(cf, if stmf != nil and stmf.kind == pkName: stmf.name else: "Identity")
    result.strMethod = resolveMethod(cf, if strf != nil and strf.kind == pkName: strf.name else: "Identity")
  else:
    result.stmMethod = cmRC4
    result.strMethod = cmRC4

  let pw = block:
    var s = newSeq[byte](password.len)
    for i, c in password: s[i] = byte(c)
    s

  if result.r >= 5:
    # Revision 5 (deprecated draft, plain SHA-256) and revision 6 (AES-256,
    # iterated hash). U/O are 48 bytes: hash(32) ‖ valSalt(8) ‖ keySalt(8).
    if u.len < 48 or o.len < 48:
      raise newException(SecError, "malformed R5/R6 /U or /O entry")
    let
      ue = strBytes(dictGet(enc, "UE"))
      oe = strBytes(dictGet(enc, "OE"))
      zeroIv = newSeq[byte](16)
      rev = result.r
    proc rhash(pwd, salt, udata: seq[byte]): seq[byte] =
      if rev == 5: sha256(pwd & salt & udata) else: hash2B(pwd, salt, udata)
    # try user password
    if rhash(pw, u[32 ..< 40], @[]) == u[0 ..< 32]:
      let ik = rhash(pw, u[40 ..< 48], @[])
      result.fileKey = aesCbcDecryptRaw(ik, zeroIv, ue)
      result.usedOwnerPassword = false
    elif rhash(pw, o[32 ..< 40], u[0 ..< 48]) == o[0 ..< 32]:
      let ik = rhash(pw, o[40 ..< 48], u[0 ..< 48])
      result.fileKey = aesCbcDecryptRaw(ik, zeroIv, oe)
      result.usedOwnerPassword = true
    else:
      raise newException(SecError, "incorrect password")
    result.keyLen = 32
    return

  # Revisions 2-4.
  let userKey = fileKeyFromPadded(padPassword(pw), o, id0, p, result.r,
                                  result.keyLen, result.encryptMetadata)
  let expU = computeU(userKey, id0, result.r)
  let uCmp = if result.r == 2: u else: u[0 ..< min(16, u.len)]
  if expU.len <= uCmp.len and expU == uCmp[0 ..< expU.len]:
    result.fileKey = userKey
    result.usedOwnerPassword = false
    return

  # Try as owner password.
  let userPadded = userPaddedFromOwner(pw, o, result.r, result.keyLen)
  let ownerDerivedKey = fileKeyFromPadded(userPadded, o, id0, p, result.r,
                                          result.keyLen, result.encryptMetadata)
  let expU2 = computeU(ownerDerivedKey, id0, result.r)
  if expU2.len <= uCmp.len and expU2 == uCmp[0 ..< expU2.len]:
    result.fileKey = ownerDerivedKey
    result.usedOwnerPassword = true
    return

  raise newException(SecError, "incorrect password")

# ---------------------------------------------------------------------------
# Per-object decryption
# ---------------------------------------------------------------------------

proc objectKey(h: SecHandler, num, gen: int, aes: bool): seq[byte] =
  var buf = h.fileKey
  buf.add byte(num and 0xff)
  buf.add byte((num shr 8) and 0xff)
  buf.add byte((num shr 16) and 0xff)
  buf.add byte(gen and 0xff)
  buf.add byte((gen shr 8) and 0xff)
  if aes:
    buf.add [byte('s'), byte('A'), byte('l'), byte('T')]
  let n = min(h.keyLen + 5, 16)
  md5b(buf)[0 ..< n]

proc decryptWith(h: SecHandler, m: CryptMethod, num, gen: int,
                 data: seq[byte]): seq[byte] =
  case m
  of cmIdentity:
    data
  of cmRC4:
    if data.len == 0: return data
    rc4(objectKey(h, num, gen, false), data)
  of cmAESV2:
    if data.len < 16: return data
    aesCbcDecrypt(objectKey(h, num, gen, true), data[0 ..< 16], data[16 ..< data.len])
  of cmAESV3:
    if data.len < 16: return data
    aesCbcDecrypt(h.fileKey, data[0 ..< 16], data[16 ..< data.len])

proc decryptStream*(h: SecHandler, num, gen: int, data: seq[byte]): seq[byte] =
  decryptWith(h, h.stmMethod, num, gen, data)

proc decryptString*(h: SecHandler, num, gen: int, data: seq[byte]): seq[byte] =
  decryptWith(h, h.strMethod, num, gen, data)
