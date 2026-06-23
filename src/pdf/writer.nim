# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Tie the pieces together: parse an encrypted PDF, decrypt every object's
## strings and streams, decompose object streams, and re-serialize the result
## as a clean, unencrypted, classic cross-reference PDF.

import
  std/[tables, strutils, algorithm],
  ./objects,
  ./security,
  ./inflate

type
  NotEncryptedError* = object of CatchableError
  UnlockResult* = object
    output*: seq[byte]
    usedOwnerPassword*: bool
    handler*: SecHandler

proc intVal(o: PdfObj, default = 0): int =
  if o != nil and o.kind == pkInt: int(o.i) else: default

proc decryptStrings(h: SecHandler, o: PdfObj, num, gen: int) =
  ## Recursively decrypt every literal/hex string contained in `o`.
  if o == nil: return
  case o.kind
  of pkStr:
    o.s = decryptString(h, num, gen, o.s)
  of pkArray:
    for item in o.arr: decryptStrings(h, item, num, gen)
  of pkDict:
    for k, v in o.d: decryptStrings(h, v, num, gen)
  of pkStream:
    for k, v in o.sd: decryptStrings(h, v, num, gen)
  else: discard

proc hasFlate(sd: OrderedTable[string, PdfObj]): bool =
  let f = sd.getOrDefault("Filter", nil)
  if f == nil: return false
  if f.kind == pkName: return f.name == "FlateDecode"
  if f.kind == pkArray:
    for it in f.arr:
      if it.kind == pkName and it.name == "FlateDecode": return true
  false

proc typeName(o: PdfObj): string =
  let t = dictGet(o, "Type")
  if t != nil and t.kind == pkName: t.name else: ""

proc decomposeObjStm*(sd: OrderedTable[string, PdfObj], plain: seq[byte]): seq[IndirectObj] =
  ## Extract the indirect objects packed inside a decrypted /Type /ObjStm stream.
  result = @[]
  let
    n = intVal(sd.getOrDefault("N", nil))
    first = intVal(sd.getOrDefault("First", nil))
  if n <= 0 or first <= 0: return
  let body = if hasFlate(sd): inflate(plain) else: plain
  if first > body.len: return
  # Header: N pairs of integers (objNum, relativeOffset).
  var
    nums = newSeq[int](n)
    offs = newSeq[int](n)
    i = 0
    idx = 0
  proc readInt(): int =
    while i < first and body[i] in [9'u8,10,12,13,32]: inc i
    var
      v = 0
      got = false
    while i < first and char(body[i]) in {'0'..'9'}:
      v = v * 10 + (int(body[i]) - int('0')); inc i; got = true
    if not got: return -1
    v
  while idx < n:
    let
      a = readInt()
      b = readInt()
    if a < 0 or b < 0: return
    nums[idx] = a; offs[idx] = b; inc idx
  for k in 0 ..< n:
    let
      startOff = first + offs[k]
      endOff = if k + 1 < n: first + offs[k+1] else: body.len
    if startOff > body.len or endOff > body.len or startOff > endOff: continue
    var slice = newSeq[byte](endOff - startOff)
    for j in 0 ..< slice.len: slice[j] = body[startOff + j]
    var p = initParser(slice, 0)
    result.add IndirectObj(num: nums[k], gen: 0, value: parseValue(p))

proc collectTrailer(objs: seq[IndirectObj], trailers: seq[PdfObj]):
    tuple[root, encrypt, id, info: PdfObj, size: int] =
  ## Gather /Root, /Encrypt, /ID, /Info, /Size from XRef-stream dicts and
  ## classic trailers (classic trailers take precedence).
  var
    root, encrypt, id, info: PdfObj = nil
    size = 0
  template absorb(d: PdfObj) =
    if dictGet(d, "Root") != nil: root = dictGet(d, "Root")
    if dictGet(d, "Encrypt") != nil: encrypt = dictGet(d, "Encrypt")
    if dictGet(d, "ID") != nil: id = dictGet(d, "ID")
    if dictGet(d, "Info") != nil: info = dictGet(d, "Info")
    size = max(size, intVal(dictGet(d, "Size")))
  for io in objs:
    if io.value != nil and io.value.kind == pkStream and typeName(io.value) == "XRef":
      absorb(io.value)
  for t in trailers:
    absorb(t)
  (root, encrypt, id, info, size)

proc unlock*(data: seq[byte], password: string): UnlockResult =
  ## Decrypt `data` using `password`, returning the unlocked PDF bytes.
  if data.len == 0:
    raise newException(CatchableError, "empty input")
  let scanned = scanObjects(data)
  # latest definition of each object number wins
  var latest = initOrderedTable[int, IndirectObj]()
  for io in scanned:
    latest[io.num] = io

  let trailers = scanTrailers(data)
  let (root, encryptRef, idArr, infoRef, size) = collectTrailer(scanned, trailers)
  if encryptRef == nil:
    raise newException(NotEncryptedError, "PDF is not encrypted (no /Encrypt entry)")

  var
    encNum = -1
    encDict: PdfObj = nil
  if encryptRef.kind == pkRef:
    encNum = encryptRef.rnum
    if latest.hasKey(encNum): encDict = latest[encNum].value
  elif encryptRef.kind == pkDict:
    encDict = encryptRef
  if encDict == nil:
    raise newException(CatchableError, "could not locate the /Encrypt dictionary")

  var id0: seq[byte] = @[]
  if idArr != nil and idArr.kind == pkArray and idArr.arr.len >= 1 and
     idArr.arr[0].kind == pkStr:
    id0 = idArr.arr[0].s

  let h = setupSecurity(encDict, id0, password)
  result.handler = h
  result.usedOwnerPassword = h.usedOwnerPassword

  # Decrypt every object; decompose object streams.
  var
    final = initOrderedTable[int, IndirectObj]()
    extracted: seq[IndirectObj] = @[]
  for num, io in latest:
    if num == encNum: continue
    let v = io.value
    if v == nil: continue
    if v.kind == pkStream and typeName(v) == "XRef":
      continue                              # dropped; we rebuild the xref
    decryptStrings(h, v, io.num, io.gen)
    if v.kind == pkStream:
      let
        tn = typeName(v)
        exemptMeta = (tn == "Metadata") and (not h.encryptMetadata)
      if not exemptMeta:
        v.data = decryptStream(h, io.num, io.gen, v.data)
      if tn == "ObjStm":
        for inner in decomposeObjStm(v.sd, v.data):
          extracted.add inner
        continue                            # drop the ObjStm container
    final[num] = io

  # Add objects extracted from ObjStms (do not override direct objects).
  for io in extracted:
    if not final.hasKey(io.num):
      final[io.num] = io

  # Serialize as a fresh classic-xref PDF.
  var nums: seq[int] = @[]
  for num in final.keys: nums.add num
  nums.sort()

  var outp: seq[byte] = @[]
  proc addS(s: string) =
    for c in s: outp.add byte(c)
  addS("%PDF-1.7\n")
  outp.add [byte('%'), 0xe2'u8, 0xe3, 0xcf, 0xd3]
  outp.add byte('\n')

  var
    offsets = initTable[int, int]()
    maxNum = 0
  for num in nums:
    let io = final[num]
    offsets[num] = outp.len
    addS($num & " " & $io.gen & " obj\n")
    serialize(io.value, outp)
    addS("\nendobj\n")
    maxNum = max(maxNum, num)

  let xrefPos = outp.len
  addS("xref\n")
  addS("0 1\n")
  addS("0000000000 65535 f\r\n")
  # contiguous runs of present object numbers
  var k = 0
  while k < nums.len:
    var j = k
    while j + 1 < nums.len and nums[j+1] == nums[j] + 1: inc j
    addS($nums[k] & " " & $(j - k + 1) & "\n")
    for t in k .. j:
      let num = nums[t]
      let line = align($offsets[num], 10, '0') & " " &
                 align($final[num].gen, 5, '0') & " n\r\n"
      addS(line)
    k = j + 1

  addS("trailer\n")
  var tdict = PdfObj(kind: pkDict)
  tdict.d["Size"] = PdfObj(kind: pkInt, i: int64(max(maxNum + 1, size)))
  if root != nil: tdict.d["Root"] = root
  if infoRef != nil: tdict.d["Info"] = infoRef
  if idArr != nil: tdict.d["ID"] = idArr
  serialize(tdict, outp)
  addS("\nstartxref\n" & $xrefPos & "\n%%EOF\n")

  result.output = outp
