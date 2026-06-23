# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Pure-Nim DEFLATE (RFC 1951) decompressor, with optional zlib (RFC 1950)
## header handling. Used to decompress PDF object streams (/Type /ObjStm) so
## the objects packed inside them can be re-emitted as normal indirect objects.

type
  InflateError* = object of CatchableError
  BitReader = object
    data: ptr UncheckedArray[byte]
    len: int
    pos: int       ## byte position
    bitBuf: uint32
    bitCnt: int

proc initBitReader(data: openArray[byte]): BitReader =
  result.len = data.len
  if data.len > 0:
    result.data = cast[ptr UncheckedArray[byte]](unsafeAddr data[0])

proc getBit(br: var BitReader): int =
  if br.bitCnt == 0:
    if br.pos >= br.len:
      raise newException(InflateError, "unexpected end of deflate stream")
    br.bitBuf = uint32(br.data[br.pos])
    inc br.pos
    br.bitCnt = 8
  result = int(br.bitBuf and 1)
  br.bitBuf = br.bitBuf shr 1
  dec br.bitCnt

proc getBits(br: var BitReader, n: int): int =
  var v = 0
  for i in 0 ..< n:
    v = v or (getBit(br) shl i)
  v

# --- Huffman ---

type Huffman = object
  counts: array[16, int]      ## number of codes of each bit length
  symbols: seq[int]           ## symbols sorted by code

proc buildHuffman(lengths: openArray[int]): Huffman =
  for l in lengths:
    if l > 0: inc result.counts[l]
  result.symbols = newSeq[int](lengths.len)
  var
    offsets: array[16, int]
    sum = 0
  for i in 1 ..< 16:
    offsets[i] = sum
    sum += result.counts[i]
  for sym in 0 ..< lengths.len:
    if lengths[sym] > 0:
      result.symbols[offsets[lengths[sym]]] = sym
      inc offsets[lengths[sym]]

proc decodeSym(br: var BitReader, h: Huffman): int =
  var
    code = 0
    first = 0
    index = 0
  for length in 1 ..< 16:
    code = code or getBit(br)
    let count = h.counts[length]
    if code - first < count:
      return h.symbols[index + (code - first)]
    index += count
    first += count
    first = first shl 1
    code = code shl 1
  raise newException(InflateError, "invalid Huffman code")

const
  lenBase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
  lenExtra = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
  distBase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
              1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
  distExtra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
  codeLengthOrder = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]

proc inflateBlockData(br: var BitReader, lit, dist: Huffman, outp: var seq[byte]) =
  while true:
    let sym = decodeSym(br, lit)
    if sym == 256:
      break
    elif sym < 256:
      outp.add byte(sym)
    else:
      let li = sym - 257
      if li >= lenBase.len:
        raise newException(InflateError, "invalid length symbol")
      let length = lenBase[li] + getBits(br, lenExtra[li])
      let dsym = decodeSym(br, dist)
      if dsym >= distBase.len:
        raise newException(InflateError, "invalid distance symbol")
      let distance = distBase[dsym] + getBits(br, distExtra[dsym])
      if distance > outp.len:
        raise newException(InflateError, "distance too far back")
      var start = outp.len - distance
      for _ in 0 ..< length:
        outp.add outp[start]
        inc start

proc fixedTables(): (Huffman, Huffman) =
  var litLen = newSeq[int](288)
  for i in 0 ..< 144: litLen[i] = 8
  for i in 144 ..< 256: litLen[i] = 9
  for i in 256 ..< 280: litLen[i] = 7
  for i in 280 ..< 288: litLen[i] = 8
  var distLen = newSeq[int](30)
  for i in 0 ..< 30: distLen[i] = 5
  (buildHuffman(litLen), buildHuffman(distLen))

proc dynamicTables(br: var BitReader): (Huffman, Huffman) =
  let
    hlit = getBits(br, 5) + 257
    hdist = getBits(br, 5) + 1
    hclen = getBits(br, 4) + 4
  var clLengths = newSeq[int](19)
  for i in 0 ..< hclen:
    clLengths[codeLengthOrder[i]] = getBits(br, 3)
  let clTree = buildHuffman(clLengths)
  var lengths = newSeq[int](hlit + hdist)
  var i = 0
  while i < hlit + hdist:
    let sym = decodeSym(br, clTree)
    if sym < 16:
      lengths[i] = sym
      inc i
    elif sym == 16:
      if i == 0: raise newException(InflateError, "invalid repeat")
      let
        prev = lengths[i-1]
        rep = getBits(br, 2) + 3
      for _ in 0 ..< rep:
        lengths[i] = prev; inc i
    elif sym == 17:
      let rep = getBits(br, 3) + 3
      for _ in 0 ..< rep:
        lengths[i] = 0; inc i
    else: # 18
      let rep = getBits(br, 7) + 11
      for _ in 0 ..< rep:
        lengths[i] = 0; inc i
  (buildHuffman(lengths[0 ..< hlit]), buildHuffman(lengths[hlit ..< hlit + hdist]))

proc inflateRaw*(data: openArray[byte]): seq[byte] =
  ## Decompress a raw DEFLATE stream (RFC 1951).
  result = newSeq[byte]()
  var br = initBitReader(data)
  while true:
    let
      final = getBit(br)
      btype = getBits(br, 2)
    case btype
    of 0:  # stored
      br.bitBuf = 0; br.bitCnt = 0   # align to byte boundary
      if br.pos + 4 > br.len:
        raise newException(InflateError, "truncated stored block")
      let len = int(br.data[br.pos]) or (int(br.data[br.pos+1]) shl 8)
      br.pos += 4   # skip LEN and NLEN
      if br.pos + len > br.len:
        raise newException(InflateError, "truncated stored data")
      for _ in 0 ..< len:
        result.add br.data[br.pos]; inc br.pos
    of 1:
      let (lit, dist) = fixedTables()
      inflateBlockData(br, lit, dist, result)
    of 2:
      let (lit, dist) = dynamicTables(br)
      inflateBlockData(br, lit, dist, result)
    else:
      raise newException(InflateError, "invalid block type")
    if final == 1:
      break

proc inflate*(data: openArray[byte]): seq[byte] =
  ## Decompress, auto-detecting a zlib header (RFC 1950). PDF FlateDecode
  ## streams are zlib-wrapped; the trailing Adler-32 checksum is ignored.
  if data.len >= 2:
    let
      cmf = int(data[0])
      flg = int(data[1])
    # zlib: low nibble of CMF is 8 (deflate) and (CMF*256+FLG) % 31 == 0
    if (cmf and 0x0f) == 8 and ((cmf * 256 + flg) mod 31) == 0:
      var start = 2
      if (flg and 0x20) != 0:   # FDICT present
        start += 4
      return inflateRaw(data.toOpenArray(start, data.len - 1))
  inflateRaw(data)
