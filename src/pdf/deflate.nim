# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Pure-Nim DEFLATE (RFC 1951) compressor with a zlib (RFC 1950) wrapper — the
## inverse of inflate.nim. Used to (re)compress PDF streams and object streams
## with /Filter /FlateDecode.
##
## The encoder runs LZ77 with a hash-chain match finder and lazy matching, then
## encodes the token stream three ways — stored, fixed Huffman and *dynamic*
## Huffman — and keeps whichever is smallest. Dynamic Huffman is what lets it
## beat a weakly-compressed source stream on recompression. Every output is
## verifiable by round-tripping through inflate.nim.

import std/algorithm

const
  minMatch = 3
  maxMatch = 258
  windowSize = 32768
  hashBits = 15
  hashSize = 1 shl hashBits
  hashMask = hashSize - 1
  maxChain = 1024
  maxStored = 65535

  lenBase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,
             115,131,163,195,227,258]
  lenExtra = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
  distBase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
              1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
  distExtra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
  # order in which code-length-code lengths are transmitted (RFC 1951 §3.2.7)
  codeLengthOrder = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]

# ---------------------------------------------------------------------------
# Bit writer (LSB-first within a byte, matching inflate.nim's reader)
# ---------------------------------------------------------------------------

type BitWriter = object
  data: seq[byte]
  acc: uint32
  nbits: int

proc putBits(bw: var BitWriter, value, n: int) =
  ## Append the low `n` bits of `value`, least-significant bit first.
  if n > 0:
    bw.acc = bw.acc or (uint32(value and ((1 shl n) - 1)) shl bw.nbits)
    bw.nbits += n
    while bw.nbits >= 8:
      bw.data.add byte(bw.acc and 0xff)
      bw.acc = bw.acc shr 8
      bw.nbits -= 8

proc putCode(bw: var BitWriter, code, len: int) =
  ## Emit a Huffman code, most-significant bit first (as DEFLATE requires).
  var c = 0
  for i in 0 ..< len:
    c = (c shl 1) or ((code shr i) and 1)
  bw.putBits(c, len)

proc align(bw: var BitWriter) =
  if bw.nbits > 0:
    bw.data.add byte(bw.acc and 0xff)
    bw.acc = 0
    bw.nbits = 0

# ---------------------------------------------------------------------------
# Huffman: canonical codes and length-limited code-length generation
# ---------------------------------------------------------------------------

proc buildCanonical(lengths: openArray[int]): seq[int] =
  ## Canonical Huffman codes for the given per-symbol bit lengths (RFC 1951
  ## §3.2.2). Symbols with length 0 get code 0 (unused).
  var maxLen = 0
  for l in lengths:
    if l > maxLen: maxLen = l
  result = newSeq[int](lengths.len)
  if maxLen == 0: return
  var blCount = newSeq[int](maxLen + 1)
  for l in lengths:
    if l > 0: inc blCount[l]
  var nextCode = newSeq[int](maxLen + 2)
  var code = 0
  for bits in 1 .. maxLen:
    code = (code + blCount[bits - 1]) shl 1
    nextCode[bits] = code
  for sym in 0 ..< lengths.len:
    let l = lengths[sym]
    if l > 0:
      result[sym] = nextCode[l]
      inc nextCode[l]

proc huffmanLengths(freq: seq[int], maxBits: int): seq[int] =
  ## Optimal-ish Huffman bit lengths, limited to `maxBits` (zlib-style overflow
  ## correction). Least frequent symbols receive the longest codes.
  let n = freq.len
  result = newSeq[int](n)
  var used: seq[int] = @[]
  for s in 0 ..< n:
    if freq[s] > 0: used.add s
  if used.len == 0: return
  if used.len == 1:
    result[used[0]] = 1                       # one symbol → a single 1-bit code
    return

  let m = used.len
  var
    nf = newSeq[int](2 * m)                    # node frequencies
    parent = newSeq[int](2 * m)
  for i in 0 ..< 2 * m: parent[i] = -1
  for i in 0 ..< m: nf[i] = freq[used[i]]

  # Binary min-heap over node indices, keyed by nf.
  var heap = newSeq[int](m)
  for i in 0 ..< m: heap[i] = i
  var hlen = m
  proc siftDown(start: int) =
    var root = start
    while true:
      var child = 2 * root + 1
      if child >= hlen: break
      if child + 1 < hlen and nf[heap[child + 1]] < nf[heap[child]]: inc child
      if nf[heap[child]] < nf[heap[root]]:
        swap heap[root], heap[child]; root = child
      else: break
  for start in countdown(m div 2 - 1, 0): siftDown(start)
  proc popMin(): int =
    result = heap[0]
    dec hlen
    heap[0] = heap[hlen]
    siftDown(0)
  proc push(node: int) =
    var c = hlen
    heap[c] = node
    inc hlen
    while c > 0:
      let p = (c - 1) div 2
      if nf[heap[c]] < nf[heap[p]]:
        swap heap[c], heap[p]; c = p
      else: break

  var next = m
  while hlen > 1:
    let a = popMin()
    let b = popMin()
    nf[next] = nf[a] + nf[b]
    parent[a] = next; parent[b] = next
    push(next)
    inc next
  let root = next - 1

  var depth = newSeq[int](next)
  for i in countdown(next - 1, 0):
    depth[i] = if i == root: 0 else: depth[parent[i]] + 1

  var overflow = 0
  var blCount = newSeq[int](maxBits + 2)
  for i in 0 ..< m:
    var d = depth[i]
    if d > maxBits: d = maxBits; inc overflow
    inc blCount[d]
  while overflow > 0:                          # push overlong codes down a level
    var bits = maxBits - 1
    while blCount[bits] == 0: dec bits
    dec blCount[bits]
    blCount[bits + 1] += 2
    dec blCount[maxBits]
    overflow -= 2

  # Assign the longest lengths to the least frequent symbols.
  var order = used
  order.sort(proc(a, b: int): int = cmp(freq[a], freq[b]))
  var oi = 0
  for bits in countdown(maxBits, 1):
    var c = blCount[bits]
    while c > 0:
      result[order[oi]] = bits
      inc oi; dec c

# Precomputed fixed-Huffman tables (RFC 1951 §3.2.6).
proc fixedLitLengths(): seq[int] =
  result = newSeq[int](288)
  for i in 0 ..< 144: result[i] = 8
  for i in 144 ..< 256: result[i] = 9
  for i in 256 ..< 280: result[i] = 7
  for i in 280 ..< 288: result[i] = 8

let
  fixedLitLens = fixedLitLengths()
  fixedLitCodes = buildCanonical(fixedLitLens)
  fixedDistLens = block:
    var s = newSeq[int](30)
    for i in 0 ..< 30: s[i] = 5
    s
  fixedDistCodes = buildCanonical(fixedDistLens)

# ---------------------------------------------------------------------------
# Symbol lookup for match lengths / distances
# ---------------------------------------------------------------------------

proc lenSymbol(length: int): int =
  var idx = lenBase.len - 1
  while idx > 0 and length < lenBase[idx]: dec idx
  idx

proc distSymbol(dist: int): int =
  var idx = distBase.len - 1
  while idx > 0 and dist < distBase[idx]: dec idx
  idx

# ---------------------------------------------------------------------------
# LZ77 with lazy matching
# ---------------------------------------------------------------------------

type Token = object
  length: int          ## 0 → literal; otherwise a match length (3..258)
  value: int           ## literal byte, or match distance

proc hash3v(input: openArray[byte], i: int): int {.inline.} =
  ((int(input[i]) shl 10) xor (int(input[i+1]) shl 5) xor int(input[i+2])) and hashMask

proc findMatch(input: openArray[byte], prev: seq[int], startJ, i, n: int): (int, int) =
  ## Longest match for position `i`, following the hash chain from `startJ`
  ## (the previous occupant of i's hash bucket). len 0 means no usable match.
  var
    j = startJ
    chain = 0
    bestLen = minMatch - 1
    bestDist = 0
  while j >= 0 and chain < maxChain:
    let dist = i - j
    if dist > windowSize: break
    if i + bestLen < n and input[j + bestLen] == input[i + bestLen]:  # cheap reject
      var l = 0
      while l < maxMatch and i + l < n and input[j + l] == input[i + l]: inc l
      if l > bestLen:
        bestLen = l; bestDist = dist
        if l >= maxMatch: break
    j = prev[j]
    inc chain
  if bestLen >= minMatch: (bestLen, bestDist) else: (0, 0)

proc lz77(input: openArray[byte]): tuple[tokens: seq[Token], litFreq, distFreq: seq[int]] =
  let n = input.len
  var
    tokens: seq[Token] = @[]
    litFreq = newSeq[int](288)
    distFreq = newSeq[int](30)
  litFreq[256] = 1                              # end-of-block always emitted
  var
    head = newSeq[int](hashSize)
    prev = newSeq[int](max(n, 1))
  for k in 0 ..< hashSize: head[k] = -1

  template insert(pos: int) =                   # add pos to its hash chain
    if pos + minMatch <= n:
      let h = hash3v(input, pos)
      prev[pos] = head[h]; head[h] = pos
  template addLit(b: byte) =
    tokens.add Token(length: 0, value: int(b)); inc litFreq[int(b)]
  template addMatch(mlen, mdist: int) =
    tokens.add Token(length: mlen, value: mdist)
    inc litFreq[257 + lenSymbol(mlen)]; inc distFreq[distSymbol(mdist)]

  var
    i = 0
    prevLen = 0
    prevDist = 0
    matchAvailable = false
  while i < n:
    var
      curLen = 0
      curDist = 0
    if i + minMatch <= n:                       # insert i, then search from the
      let h = hash3v(input, i)                   # chain that existed before it
      let startJ = head[h]
      prev[i] = startJ; head[h] = i
      (curLen, curDist) = findMatch(input, prev, startJ, i, n)
    if matchAvailable:
      if prevLen >= minMatch and prevLen >= curLen:
        addMatch(prevLen, prevDist)             # commit deferred match at i-1
        var k = i + 1
        let stop = (i - 1) + prevLen
        while k < stop:
          insert(k); inc k
        i = stop
        matchAvailable = false
        continue
      else:
        addLit(input[i - 1])                    # previous byte stays a literal
    prevLen = curLen; prevDist = curDist
    matchAvailable = true
    inc i
  if matchAvailable:
    addLit(input[n - 1])
  (tokens, litFreq, distFreq)

# ---------------------------------------------------------------------------
# Block encoders
# ---------------------------------------------------------------------------

proc writeTokens(bw: var BitWriter, tokens: seq[Token],
                 litCodes, litLens, distCodes, distLens: seq[int]) =
  for t in tokens:
    if t.length == 0:
      bw.putCode(litCodes[t.value], litLens[t.value])
    else:
      let ls = lenSymbol(t.length)
      bw.putCode(litCodes[257 + ls], litLens[257 + ls])
      bw.putBits(t.length - lenBase[ls], lenExtra[ls])
      let ds = distSymbol(t.value)
      bw.putCode(distCodes[ds], distLens[ds])
      bw.putBits(t.value - distBase[ds], distExtra[ds])
  bw.putCode(litCodes[256], litLens[256])       # end of block

proc encodeFixed(tokens: seq[Token]): seq[byte] =
  var bw = BitWriter()
  bw.putBits(1, 1)      # BFINAL = 1
  bw.putBits(1, 2)      # BTYPE  = 01 (fixed)
  writeTokens(bw, tokens, fixedLitCodes, fixedLitLens, fixedDistCodes, fixedDistLens)
  bw.align()
  bw.data

proc rleCodeLengths(cl: seq[int]): tuple[syms: seq[(int, int)], freq: seq[int]] =
  ## Run-length encode a code-length sequence into the code-length alphabet
  ## (symbols 0..18) per RFC 1951 §3.2.7.
  result.freq = newSeq[int](19)
  var i = 0
  while i < cl.len:
    let v = cl[i]
    var run = 1
    while i + run < cl.len and cl[i + run] == v: inc run
    if v == 0:
      while run >= 11:
        let r = min(run, 138)
        result.syms.add (18, r - 11); inc result.freq[18]; run -= r; i += r
      while run >= 3:
        let r = min(run, 10)
        result.syms.add (17, r - 3); inc result.freq[17]; run -= r; i += r
      while run > 0:
        result.syms.add (0, 0); inc result.freq[0]; dec run; inc i
    else:
      result.syms.add (v, 0); inc result.freq[v]; dec run; inc i
      while run >= 3:
        let r = min(run, 6)
        result.syms.add (16, r - 3); inc result.freq[16]; run -= r; i += r
      while run > 0:
        result.syms.add (v, 0); inc result.freq[v]; dec run; inc i

proc encodeDynamic(tokens: seq[Token], litFreq, distFreq: seq[int]): seq[byte] =
  var litLens = huffmanLengths(litFreq, 15)
  var distLens = huffmanLengths(distFreq, 15)

  var hlit = 286
  while hlit > 257 and litLens[hlit - 1] == 0: dec hlit
  var hdist = 30
  while hdist > 1 and distLens[hdist - 1] == 0: dec hdist
  var anyDist = false
  for k in 0 ..< 30:
    if distLens[k] > 0: anyDist = true
  if not anyDist:                               # need at least one distance code
    distLens[0] = 1; hdist = 1

  var cl: seq[int] = @[]
  for k in 0 ..< hlit: cl.add litLens[k]
  for k in 0 ..< hdist: cl.add distLens[k]
  let (clSyms, clFreq) = rleCodeLengths(cl)
  let clLens = huffmanLengths(clFreq, 7)
  let clCodes = buildCanonical(clLens)

  var hclen = 19
  while hclen > 4 and clLens[codeLengthOrder[hclen - 1]] == 0: dec hclen

  let litCodes = buildCanonical(litLens)
  let distCodes = buildCanonical(distLens)

  var bw = BitWriter()
  bw.putBits(1, 1)      # BFINAL = 1
  bw.putBits(2, 2)      # BTYPE  = 10 (dynamic)
  bw.putBits(hlit - 257, 5)
  bw.putBits(hdist - 1, 5)
  bw.putBits(hclen - 4, 4)
  for k in 0 ..< hclen:
    bw.putBits(clLens[codeLengthOrder[k]], 3)
  for (sym, extra) in clSyms:
    bw.putCode(clCodes[sym], clLens[sym])
    case sym
    of 16: bw.putBits(extra, 2)
    of 17: bw.putBits(extra, 3)
    of 18: bw.putBits(extra, 7)
    else: discard
  writeTokens(bw, tokens, litCodes, litLens, distCodes, distLens)
  bw.align()
  bw.data

proc deflateStored(input: openArray[byte]): seq[byte] =
  ## Uncompressed stored blocks (RFC 1951 §3.2.4): always valid, used for
  ## incompressible data.
  result = @[]
  var pos = 0
  while true:
    let blen = min(maxStored, input.len - pos)
    let final = pos + blen >= input.len
    result.add byte(if final: 1 else: 0)        # BFINAL in bit 0, BTYPE = 00
    result.add byte(blen and 0xff)
    result.add byte((blen shr 8) and 0xff)
    let nlen = (not blen) and 0xffff
    result.add byte(nlen and 0xff)
    result.add byte((nlen shr 8) and 0xff)
    for k in 0 ..< blen: result.add input[pos + k]
    pos += blen
    if final: break

proc deflate*(input: openArray[byte]): seq[byte] =
  ## Raw DEFLATE stream (RFC 1951): the smallest of the stored, fixed-Huffman
  ## and dynamic-Huffman encodings.
  let (tokens, litFreq, distFreq) = lz77(input)
  result = deflateStored(input)
  let fixed = encodeFixed(tokens)
  if fixed.len < result.len: result = fixed
  let dynamic = encodeDynamic(tokens, litFreq, distFreq)
  if dynamic.len < result.len: result = dynamic

# ---------------------------------------------------------------------------
# zlib wrapper (RFC 1950) — this is what PDF /FlateDecode expects
# ---------------------------------------------------------------------------

proc adler32(data: openArray[byte]): uint32 =
  const modAdler = 65521'u32
  var a = 1'u32
  var b = 0'u32
  for x in data:
    a = (a + uint32(x)) mod modAdler
    b = (b + a) mod modAdler
  (b shl 16) or a

proc zlibCompress*(input: openArray[byte]): seq[byte] =
  ## DEFLATE `input` and wrap it in a zlib container with a trailing Adler-32.
  result = @[0x78'u8, 0x9c'u8]     # CM=deflate, 32K window, no dict
  result.add deflate(input)
  let a = adler32(input)
  result.add byte((a shr 24) and 0xff)
  result.add byte((a shr 16) and 0xff)
  result.add byte((a shr 8) and 0xff)
  result.add byte(a and 0xff)
