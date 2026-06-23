# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## End-to-end and unit tests for the PDF layer.
##
## The fixtures in tests/fixtures were produced with pypdf from a single base
## PDF whose page draws the text "Hello pdftools SECRET 42" and whose /Info
## /Title is "Confidential Title String". User password: user123, owner: owner456.

import
  std/tables,
  ../src/pdf/objects,
  ../src/pdf/security,
  ../src/pdf/writer

var failures = 0
proc check(name: string, cond: bool) =
  if cond: echo "ok   ", name
  else: (inc failures; echo "FAIL ", name)

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

# ---------------------------------------------------------------------------
# End-to-end: decrypt each fixture with the user password.
# ---------------------------------------------------------------------------
for name, raw in fixtures.items:
  let
    data = bytesOf(raw)
    res = unlock(data, "user123")
  # The decrypted /Info /Title must round-trip.
  var titleOk = false
  for io in scanObjects(res.output):
    if findString(io.value, "Confidential Title String"): titleOk = true
  check name & ": title string decrypted", titleOk
  # The output must no longer be encrypted: a second unlock reports so.
  var stripped = false
  try:
    discard unlock(res.output, "")
  except NotEncryptedError:
    stripped = true
  check name & ": /Encrypt removed from output", stripped

# ---------------------------------------------------------------------------
# Owner password and wrong password.
# ---------------------------------------------------------------------------
block:
  let
    data = bytesOf(r6Fixture)
    res = unlock(data, "owner456")
  check "owner password accepted", res.usedOwnerPassword
  var rejected = false
  try:
    discard unlock(data, "definitely-wrong")
  except SecError:
    rejected = true
  check "wrong password rejected", rejected

# ---------------------------------------------------------------------------
# Unit test: object-stream decomposition.
# ---------------------------------------------------------------------------
block:
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
  check "ObjStm: extracted 3 objects", extracted.len == 3
  if extracted.len == 3:
    check "ObjStm: object numbers", extracted[0].num == 10 and
      extracted[1].num == 11 and extracted[2].num == 12
    check "ObjStm: inner dict parsed",
      extracted[0].value.kind == pkDict and
      dictGet(extracted[0].value, "Type").name == "Catalog"
    check "ObjStm: inner string parsed",
      extracted[1].value.kind == pkStr and
      strOf(extracted[1].value.s) == "an inner string"

# ---------------------------------------------------------------------------
# Unit test: not-encrypted input is reported.
# ---------------------------------------------------------------------------
block:
  let data = bytesOf(baseFixture)
  var reported = false
  try:
    discard unlock(data, "")
  except NotEncryptedError:
    reported = true
  check "plain PDF reported as not encrypted", reported

if failures == 0:
  echo "\nALL PDF TESTS PASSED"
else:
  echo "\n", failures, " FAILURES"
  quit(1)
