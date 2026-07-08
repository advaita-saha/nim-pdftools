# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Lossless PDF size reduction: parse a PDF, FlateDecode every stream that is
## not already compressed, pack the small non-stream objects into a compressed
## /Type /ObjStm, and rebuild the cross-reference as a /Type /XRef stream. No
## content is re-sampled or re-encoded, so rendering is byte-for-byte identical.
##
## This is the inverse philosophy of writer.nim's `unlock`, which expands
## everything to a plaintext classic-xref layout; here we contract it.

import
  std/[tables, algorithm],
  ./objects,
  ./inflate,
  ./deflate,
  ./writer         # reuse decomposeObjStm (which handles Flate object streams)

type
  EncryptedError* = object of CatchableError
  CompressResult* = object
    output*: seq[byte]
    originalSize*: int
    compressedSize*: int

proc intVal(o: PdfObj, default = 0): int =
  if o != nil and o.kind == pkInt: int(o.i) else: default

proc typeName(o: PdfObj): string =
  let t = dictGet(o, "Type")
  if t != nil and t.kind == pkName: t.name else: ""

proc isFlate(f: PdfObj): bool =
  ## True if `f` is exactly /FlateDecode (a bare name or a one-element array).
  if f == nil: return false
  if f.kind == pkName: return f.name == "FlateDecode"
  if f.kind == pkArray and f.arr.len == 1 and f.arr[0].kind == pkName:
    return f.arr[0].name == "FlateDecode"
  false

proc byteWidth(v: int): int =
  var x = v
  result = 1
  while x > 0xff:
    x = x shr 8
    inc result

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

proc compress*(data: seq[byte]): CompressResult =
  ## Return a losslessly size-reduced copy of `data`.
  if data.len == 0:
    raise newException(CatchableError, "empty input")
  result.originalSize = data.len

  let scanned = scanObjects(data)
  var latest = initOrderedTable[int, IndirectObj]()
  for io in scanned:                       # latest definition of a number wins
    latest[io.num] = io
  let trailers = scanTrailers(data)
  let (root, encryptRef, idArr, infoRef, _) = collectTrailer(scanned, trailers)
  if encryptRef != nil:
    raise newException(EncryptedError,
      "PDF is encrypted; run 'pdftools unlock' first")

  # Flatten: drop XRef streams, decompose ObjStm containers, keep everything
  # else. Direct definitions take precedence over objects unpacked from ObjStms.
  var
    final = initOrderedTable[int, IndirectObj]()
    extracted: seq[IndirectObj] = @[]
  for num, io in latest:
    if num <= 0: continue
    let v = io.value
    if v == nil: continue
    if v.kind == pkStream:
      let tn = typeName(v)
      if tn == "XRef": continue              # rebuilt as a fresh /XRef stream
      if tn == "ObjStm":
        for inner in decomposeObjStm(v.sd, v.data): extracted.add inner
        continue                             # drop the container
    final[num] = io
  for io in extracted:
    if not final.hasKey(io.num): final[io.num] = io

  # Compress stream data. Uncompressed streams get FlateDecode; already-Flate
  # streams are inflated and re-deflated with our stronger encoder, keeping
  # whichever is smaller. Both are lossless — for Flate we only swap the outer
  # DEFLATE layer, so any /DecodeParms predictor is preserved untouched. Other
  # filters (DCTDecode/JPEG, etc.) are never re-encoded, so image quality is
  # unchanged.
  for num, io in final:
    let v = io.value
    if v == nil or v.kind != pkStream or v.data.len == 0: continue
    let filt = v.sd.getOrDefault("Filter", nil)
    if filt == nil:
      let z = zlibCompress(v.data)
      if z.len < v.data.len:
        v.data = z
        v.sd["Filter"] = PdfObj(kind: pkName, name: "FlateDecode")
    elif isFlate(filt):
      try:
        let z = zlibCompress(inflate(v.data))
        if z.len < v.data.len: v.data = z       # /Filter stays FlateDecode
      except CatchableError:
        discard                                 # unparseable stream: leave it


  # Partition objects: streams (and any gen != 0) stay top-level (xref type 1);
  # plain gen-0 objects get packed into an object stream (xref type 2).
  var
    nums: seq[int] = @[]
    maxNum = 0
  for num in final.keys:
    nums.add num
    maxNum = max(maxNum, num)
  nums.sort()

  var
    streamNums: seq[int] = @[]
    packNums: seq[int] = @[]
  for num in nums:
    let io = final[num]
    if io.value.kind == pkStream or io.gen != 0: streamNums.add num
    else: packNums.add num

  var nextNum = maxNum + 1
  var objStmNum = -1
  if packNums.len > 0:
    objStmNum = nextNum; inc nextNum
  let xrefNum = nextNum

  # Build the object stream body: header of "objNum relOffset" pairs followed by
  # the concatenated object bodies; offsets are relative to /First.
  var
    objStm: PdfObj = nil
    objStmIndex = initTable[int, int]()
  if packNums.len > 0:
    var
      bodies: seq[byte] = @[]
      offs: seq[int] = @[]
    for k, num in packNums:
      objStmIndex[num] = k
      offs.add bodies.len
      serialize(final[num].value, bodies)
      bodies.add byte(' ')
    var header = ""
    for k, num in packNums:
      header.add $num & " " & $offs[k] & " "
    var body: seq[byte] = @[]
    for c in header: body.add byte(c)
    let first = body.len
    for b in bodies: body.add b
    var sd = initOrderedTable[string, PdfObj]()
    sd["Type"] = PdfObj(kind: pkName, name: "ObjStm")
    sd["N"] = PdfObj(kind: pkInt, i: int64(packNums.len))
    sd["First"] = PdfObj(kind: pkInt, i: int64(first))
    sd["Filter"] = PdfObj(kind: pkName, name: "FlateDecode")
    objStm = PdfObj(kind: pkStream, sd: sd, data: zlibCompress(body))

  # ---- Serialize the file ----
  var outp: seq[byte] = @[]
  proc addS(s: string) =
    for c in s: outp.add byte(c)
  addS("%PDF-1.7\n")
  outp.add [byte('%'), 0xe2'u8, 0xe3, 0xcf, 0xd3]
  outp.add byte('\n')

  var offsets = initTable[int, int]()
  for num in streamNums:
    let io = final[num]
    offsets[num] = outp.len
    addS($num & " " & $io.gen & " obj\n")
    serialize(io.value, outp)
    addS("\nendobj\n")
  if objStm != nil:
    offsets[objStmNum] = outp.len
    addS($objStmNum & " 0 obj\n")
    serialize(objStm, outp)
    addS("\nendobj\n")

  # The xref stream is the final object; its own offset is where we are now.
  let xrefOffset = outp.len
  offsets[xrefNum] = xrefOffset

  var maxField2 = 0
  for num, off in offsets: maxField2 = max(maxField2, off)
  let
    w1 = 1
    w2 = byteWidth(maxField2)
    w3 = byteWidth(max(65535, packNums.len))

  proc putField(buf: var seq[byte], value, width: int) =
    for k in countdown(width - 1, 0):
      buf.add byte((value shr (8 * k)) and 0xff)

  var xdata: seq[byte] = @[]
  for n in 0 .. xrefNum:
    if n != 0 and offsets.hasKey(n):
      let gen = if n == objStmNum or n == xrefNum: 0 else: final[n].gen
      putField(xdata, 1, w1); putField(xdata, offsets[n], w2); putField(xdata, gen, w3)
    elif n != 0 and objStmIndex.hasKey(n):
      putField(xdata, 2, w1); putField(xdata, objStmNum, w2); putField(xdata, objStmIndex[n], w3)
    else:                                    # object 0 and any gaps: free
      putField(xdata, 0, w1); putField(xdata, 0, w2); putField(xdata, 65535, w3)

  var xsd = initOrderedTable[string, PdfObj]()
  xsd["Type"] = PdfObj(kind: pkName, name: "XRef")
  xsd["Size"] = PdfObj(kind: pkInt, i: int64(xrefNum + 1))
  if root != nil: xsd["Root"] = root
  if infoRef != nil: xsd["Info"] = infoRef
  if idArr != nil: xsd["ID"] = idArr
  var warr = PdfObj(kind: pkArray)
  warr.arr = @[PdfObj(kind: pkInt, i: int64(w1)),
               PdfObj(kind: pkInt, i: int64(w2)),
               PdfObj(kind: pkInt, i: int64(w3))]
  xsd["W"] = warr
  var indexArr = PdfObj(kind: pkArray)
  indexArr.arr = @[PdfObj(kind: pkInt, i: 0),
                   PdfObj(kind: pkInt, i: int64(xrefNum + 1))]
  xsd["Index"] = indexArr
  xsd["Filter"] = PdfObj(kind: pkName, name: "FlateDecode")
  let xrefObj = PdfObj(kind: pkStream, sd: xsd, data: zlibCompress(xdata))

  addS($xrefNum & " 0 obj\n")
  serialize(xrefObj, outp)
  addS("\nendobj\n")
  addS("startxref\n" & $xrefOffset & "\n%%EOF\n")

  result.output = outp
  result.compressedSize = outp.len
