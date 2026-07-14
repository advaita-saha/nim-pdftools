# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## End-to-end tests for the `compress` command. The fixtures are the same ones
## used by test_pdf; we first `unlock` the encrypted ones to obtain plaintext
## PDFs, then compress and re-validate.

import
  std/[tables, strutils],
  unittest2,
  ../src/pdf/objects,
  ../src/pdf/inflate,
  ../src/pdf/writer,
  ../src/pdf/compress

const
  baseFixture = staticRead("fixtures/base.pdf")
  rc4Fixture = staticRead("fixtures/rc4-128.pdf")
  objstmFixture = staticRead("fixtures/objstm-aes256.pdf")

proc bytesOf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc strOf(b: seq[byte]): string =
  result = newStringOfCap(b.len)
  for x in b: result.add char(x)

proc isFlate(sd: OrderedTable[string, PdfObj]): bool =
  let f = sd.getOrDefault("Filter", nil)
  f != nil and f.kind == pkName and f.name == "FlateDecode"

proc findStr(o: PdfObj, want: string): bool =
  if o == nil: return false
  case o.kind
  of pkStr: return strOf(o.s) == want
  of pkArray:
    for it in o.arr:
      if findStr(it, want): return true
  of pkDict:
    for _, v in o.d:
      if findStr(v, want): return true
  of pkStream:
    for _, v in o.sd:
      if findStr(v, want): return true
  else: discard
  false

proc beRead(data: seq[byte], pos, width: int): int =
  for k in 0 ..< width: result = (result shl 8) or int(data[pos + k])

# --- helpers to synthesize PDFs with known stream payloads ---

proc adler32(data: seq[byte]): uint32 =
  var a = 1'u32
  var b = 0'u32
  for x in data:
    a = (a + uint32(x)) mod 65521
    b = (b + a) mod 65521
  (b shl 16) or a

proc weakFlate(data: seq[byte]): seq[byte] =
  ## A valid zlib /FlateDecode stream that uses a single *stored* block, i.e.
  ## essentially no compression — models a source that compressed poorly.
  doAssert data.len <= 65535
  result = @[0x78'u8, 0x01'u8, 0x01'u8]         # header + BFINAL=1, BTYPE=00
  result.add byte(data.len and 0xff)
  result.add byte((data.len shr 8) and 0xff)
  let nlen = (not data.len) and 0xffff
  result.add byte(nlen and 0xff)
  result.add byte((nlen shr 8) and 0xff)
  for b in data: result.add b
  let a = adler32(data)
  for sh in [24, 16, 8, 0]: result.add byte((a shr sh) and 0xff)

proc buildPdf(content: seq[byte], flate: bool): seq[byte] =
  ## Minimal 5-object PDF whose object 4 is `content` (optionally /FlateDecode).
  template add(s: string) =
    for c in s: result.add byte(c)
  add "%PDF-1.7\n"
  add "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
  add "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
  add "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >> endobj\n"
  add("4 0 obj << /Length " & $content.len &
      (if flate: " /Filter /FlateDecode" else: "") & " >>\nstream\n")
  for b in content: result.add b
  add "\nendstream endobj\n"
  add "5 0 obj << /Title (Confidential Title String) >> endobj\n"
  add "trailer << /Root 1 0 R /Info 5 0 R /Size 6 >>\n%%EOF\n"

proc contentPayload(comp: seq[byte], marker: string): seq[byte] =
  ## Decoded bytes of the (Flate) stream whose content starts with `marker`.
  let direct = scanObjects(comp)
  var all = direct
  for io in direct:
    if io.value.kind == pkStream:
      let t = dictGet(io.value, "Type")
      if t != nil and t.kind == pkName and t.name == "ObjStm":
        for inner in decomposeObjStm(io.value.sd, io.value.data): all.add inner
  for io in all:
    if io.value.kind == pkStream:
      let body = if isFlate(io.value.sd): inflate(io.value.data) else: io.value.data
      if strOf(body).startsWith(marker): return body
  @[]

## Re-parse a compressed PDF and check structural integrity: the XRef stream is
## present and every entry is consistent, and the known title/content survive.
proc validate(comp: seq[byte]) =
  let direct = scanObjects(comp)
  var
    all: seq[IndirectObj] = @[]
    xref: PdfObj = nil
  for io in direct:
    all.add io
    if io.value.kind == pkStream:
      let t = dictGet(io.value, "Type")
      if t != nil and t.kind == pkName and t.name == "XRef": xref = io.value
      if t != nil and t.kind == pkName and t.name == "ObjStm":
        for inner in decomposeObjStm(io.value.sd, io.value.data): all.add inner
  check xref != nil

  var foundTitle, foundContent = false
  for io in all:
    if findStr(io.value, "Confidential Title String"): foundTitle = true
    if io.value.kind == pkStream:
      let body = if isFlate(io.value.sd): inflate(io.value.data) else: io.value.data
      if strOf(body).contains("Hello pdftools"): foundContent = true
  check foundTitle
  check foundContent

  # Decode the cross-reference stream and verify every offset/reference.
  let w = dictGet(xref, "W")
  require w != nil and w.kind == pkArray and w.arr.len == 3
  let (w1, w2, w3) = (int(w.arr[0].i), int(w.arr[1].i), int(w.arr[2].i))
  let idx = dictGet(xref, "Index")
  require idx != nil and idx.arr.len == 2
  let count = int(idx.arr[1].i)
  check int(idx.arr[0].i) == 0
  let xbody = if isFlate(xref.sd): inflate(xref.data) else: xref.data
  require xbody.len == count * (w1 + w2 + w3)
  var pos = 0
  for n in 0 ..< count:
    let ty = beRead(xbody, pos, w1); pos += w1
    let f2 = beRead(xbody, pos, w2); pos += w2
    let f3 = beRead(xbody, pos, w3); pos += w3
    case ty
    of 0: discard
    of 1:
      let expect = $n & " " & $f3 & " obj"
      check strOf(comp[f2 ..< min(comp.len, f2 + expect.len)]) == expect
    of 2:
      check f3 < count
    else:
      check false

suite "compress":
  test "shrinks a tiny plain PDF and stays valid":
    let res = compress(bytesOf(baseFixture))
    check res.compressedSize < res.originalSize
    validate(res.output)

  test "compresses unlocked plaintext and round-trips content":
    for fx in [rc4Fixture, objstmFixture]:
      let plain = unlock(bytesOf(fx), "user123").output
      let res = compress(plain)
      check res.compressedSize <= res.originalSize
      validate(res.output)

  test "recompressing its own output is idempotent and valid":
    let once = compress(bytesOf(baseFixture)).output
    let twice = compress(once)
    check twice.compressedSize <= twice.originalSize
    validate(twice.output)

  test "refuses an encrypted PDF":
    expect EncryptedError:
      discard compress(bytesOf(rc4Fixture))

  test "Flate-compresses a large raw content stream, losslessly":
    let raw = bytesOf("Hello pdftools drawing ops ".repeat(500))
    let pdf = buildPdf(raw, flate = false)
    let res = compress(pdf)
    check res.compressedSize < res.originalSize div 3     # big win on redundant data
    validate(res.output)
    check contentPayload(res.output, "Hello pdftools") == raw

  test "recompresses a weakly-Flated stream and preserves payload":
    let raw = bytesOf("Hello pdftools drawing ops ".repeat(500))
    let pdf = buildPdf(weakFlate(raw), flate = true)      # ~uncompressed FlateDecode
    let res = compress(pdf)
    check res.compressedSize < res.originalSize div 3     # our encoder beats the weak source
    validate(res.output)
    check contentPayload(res.output, "Hello pdftools") == raw
