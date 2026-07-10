# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## End-to-end and unit tests for the PDF layer.
##
## The fixtures in tests/fixtures were produced with pypdf from a single base
## PDF whose page draws the text "Hello pdftools SECRET 42" and whose /Info
## /Title is "Confidential Title String". User password: user123, owner: owner456.

import
  std/tables,
  unittest2,
  ../src/pdf/objects,
  ../src/pdf/security,
  ../src/pdf/writer

proc bytesOf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc strOf(b: seq[byte]): string =
  result = newStringOfCap(b.len)
  for x in b: result.add char(x)

proc findString(o: PdfObj, want: string): bool =
  ## Depth-first search for a decoded string equal to `want`.
  if o == nil: return false
  case o.kind
  of pkStr: return strOf(o.s) == want
  of pkArray:
    for it in o.arr:
      if findString(it, want): return true
  of pkDict:
    for _, v in o.d:
      if findString(v, want): return true
  of pkStream:
    for _, v in o.sd:
      if findString(v, want): return true
  else: discard
  false

const fixtures = {
  "rc4-40":        staticRead("fixtures/rc4-40.pdf"),
  "rc4-128":       staticRead("fixtures/rc4-128.pdf"),
  "aes-128":       staticRead("fixtures/aes-128.pdf"),
  "aes-256-r5":    staticRead("fixtures/aes-256-r5.pdf"),
  "aes-256-r6":    staticRead("fixtures/aes-256-r6.pdf"),
  # modern PDFs with cross-reference streams + object streams (qpdf-generated)
  "objstm-aes128": staticRead("fixtures/objstm-aes128.pdf"),
  "objstm-aes256": staticRead("fixtures/objstm-aes256.pdf"),
}
const
  baseFixture = staticRead("fixtures/base.pdf")
  r6Fixture = staticRead("fixtures/aes-256-r6.pdf")

suite "decrypt fixtures with user password":
  for name, raw in fixtures.items:
    test name:
      let res = unlock(bytesOf(raw), "user123")
      # The decrypted /Info /Title must round-trip.
      var titleOk = false
      for io in scanObjects(res.output):
        if findString(io.value, "Confidential Title String"): titleOk = true
      check titleOk
      # The output must no longer be encrypted: a second unlock reports so.
      expect NotEncryptedError:
        discard unlock(res.output, "")

suite "password handling":
  test "owner password accepted":
    let res = unlock(bytesOf(r6Fixture), "owner456")
    check res.usedOwnerPassword

  test "wrong password rejected":
    let data = bytesOf(r6Fixture)
    expect SecError:
      discard unlock(data, "definitely-wrong")

suite "object streams":
  test "ObjStm decomposition":
    # Build an uncompressed ObjStm body holding three objects (10, 11, 12).
    let
      o10 = "<< /Type /Catalog /Pages 2 0 R >>"
      o11 = "(an inner string)"
      o12 = "[1 2 3]"
      header = "10 0 11 " & $o10.len & " 12 " & $(o10.len + o11.len) & " "
    # offsets are relative to /First (= header length)
    let body = header & o10 & o11 & o12
    var sd = initOrderedTable[string, PdfObj]()
    sd["N"] = PdfObj(kind: pkInt, i: 3)
    sd["First"] = PdfObj(kind: pkInt, i: int64(header.len))
    let extracted = decomposeObjStm(sd, bytesOf(body))
    require extracted.len == 3
    check extracted[0].num == 10
    check extracted[1].num == 11
    check extracted[2].num == 12
    check extracted[0].value.kind == pkDict
    check dictGet(extracted[0].value, "Type").name == "Catalog"
    check extracted[1].value.kind == pkStr
    check strOf(extracted[1].value.s) == "an inner string"

suite "plaintext input":
  test "plain PDF reported as not encrypted":
    expect NotEncryptedError:
      discard unlock(bytesOf(baseFixture), "")
