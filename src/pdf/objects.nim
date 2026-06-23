# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## A small PDF object model with a tolerant parser and a canonical serializer.
##
## We deliberately do not implement the full PDF spec — only what is needed to:
##   * scan a file for every `N G obj … endobj` indirect object,
##   * read the trailer / cross-reference-stream dictionaries (always plaintext),
##   * decrypt the strings and stream data of each object,
##   * decompose object streams (/Type /ObjStm), and
##   * write everything back out as a clean classic-xref PDF.

import
  std/[tables, strutils]

type
  PdfKind* = enum
    pkNull, pkBool, pkInt, pkReal, pkStr, pkName, pkArray, pkDict, pkRef, pkStream
  PdfObj* = ref object
    case kind*: PdfKind
    of pkNull: discard
    of pkBool: b*: bool
    of pkInt: i*: int64
    of pkReal: rawf*: string          ## original textual token (round-trips exactly)
    of pkStr: s*: seq[byte]           ## decoded string bytes
    of pkName: name*: string
    of pkArray: arr*: seq[PdfObj]
    of pkDict: d*: OrderedTable[string, PdfObj]
    of pkRef: rnum*, rgen*: int
    of pkStream:
      sd*: OrderedTable[string, PdfObj]
      data*: seq[byte]

  IndirectObj* = object
    num*, gen*: int
    value*: PdfObj

# ---------------------------------------------------------------------------
# Byte classification
# ---------------------------------------------------------------------------

proc isWs(b: byte): bool {.inline.} =
  b in [0'u8, 9, 10, 12, 13, 32]

proc isDelim(b: byte): bool {.inline.} =
  b in {byte('('), byte(')'), byte('<'), byte('>'), byte('['), byte(']'),
        byte('{'), byte('}'), byte('/'), byte('%')}

proc isRegular(b: byte): bool {.inline.} =
  not isWs(b) and not isDelim(b)

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

type Parser* = object
  data: ptr UncheckedArray[byte]
  len: int
  pos: int

proc initParser*(data: openArray[byte], start = 0): Parser =
  result.len = data.len
  result.pos = start
  if data.len > 0:
    result.data = cast[ptr UncheckedArray[byte]](unsafeAddr data[0])

proc atEnd(p: Parser): bool {.inline.} = p.pos >= p.len
proc cur(p: Parser): byte {.inline.} = p.data[p.pos]

proc skipWs(p: var Parser) =
  while p.pos < p.len:
    let b = p.data[p.pos]
    if b == byte('%'):                # comment to end of line
      while p.pos < p.len and p.data[p.pos] notin [10'u8, 13'u8]: inc p.pos
    elif isWs(b):
      inc p.pos
    else:
      break

proc matches(p: Parser, s: string): bool =
  if p.pos + s.len > p.len: return false
  for i in 0 ..< s.len:
    if p.data[p.pos + i] != byte(s[i]): return false
  true

proc parseValue*(p: var Parser): PdfObj

proc parseName(p: var Parser): PdfObj =
  inc p.pos                            # consume '/'
  var s = ""
  while p.pos < p.len and isRegular(p.data[p.pos]):
    let b = p.data[p.pos]
    if b == byte('#') and p.pos + 2 < p.len:
      s.add char(parseHexInt($char(p.data[p.pos+1]) & $char(p.data[p.pos+2])))
      inc p.pos, 3
    else:
      s.add char(b)
      inc p.pos
  PdfObj(kind: pkName, name: s)

proc parseLiteralString(p: var Parser): PdfObj =
  inc p.pos                            # consume '('
  var
    depth = 1
    s: seq[byte]
  while p.pos < p.len:
    let b = p.data[p.pos]
    if b == byte('\\'):
      inc p.pos
      if p.pos >= p.len: break
      let e = p.data[p.pos]
      case char(e)
      of 'n': s.add 10'u8; inc p.pos
      of 'r': s.add 13'u8; inc p.pos
      of 't': s.add 9'u8; inc p.pos
      of 'b': s.add 8'u8; inc p.pos
      of 'f': s.add 12'u8; inc p.pos
      of '(': s.add byte('('); inc p.pos
      of ')': s.add byte(')'); inc p.pos
      of '\\': s.add byte('\\'); inc p.pos
      of '0'..'7':
        var
          oct = 0
          n = 0
        while n < 3 and p.pos < p.len and char(p.data[p.pos]) in {'0'..'7'}:
          oct = oct * 8 + (int(p.data[p.pos]) - int('0'))
          inc p.pos; inc n
        s.add byte(oct and 0xff)
      of '\r':
        inc p.pos
        if p.pos < p.len and p.data[p.pos] == 10'u8: inc p.pos
      of '\n': inc p.pos
      else: s.add e; inc p.pos
    elif b == byte('('):
      inc depth; s.add b; inc p.pos
    elif b == byte(')'):
      dec depth
      if depth == 0: inc p.pos; break
      s.add b; inc p.pos
    else:
      s.add b; inc p.pos
  PdfObj(kind: pkStr, s: s)

proc parseHexString(p: var Parser): PdfObj =
  inc p.pos                            # consume '<'
  var hexd = ""
  while p.pos < p.len and p.data[p.pos] != byte('>'):
    let b = p.data[p.pos]
    if not isWs(b): hexd.add char(b)
    inc p.pos
  if p.pos < p.len: inc p.pos          # consume '>'
  if hexd.len mod 2 == 1: hexd.add '0'
  var s = newSeq[byte](hexd.len div 2)
  for i in 0 ..< s.len:
    s[i] = byte(parseHexInt(hexd[2*i] & $hexd[2*i+1]))
  PdfObj(kind: pkStr, s: s)

proc parseArray(p: var Parser): PdfObj =
  inc p.pos                            # consume '['
  result = PdfObj(kind: pkArray)
  while true:
    p.skipWs()
    if p.atEnd or p.cur == byte(']'):
      if not p.atEnd: inc p.pos
      break
    result.arr.add parseValue(p)

proc parseDict(p: var Parser): PdfObj =
  inc p.pos; inc p.pos                 # consume '<<'
  result = PdfObj(kind: pkDict)
  while true:
    p.skipWs()
    if p.matches(">>"):
      inc p.pos, 2; break
    if p.atEnd: break
    if p.cur != byte('/'):             # malformed; stop defensively
      inc p.pos; continue
    let key = parseName(p).name
    p.skipWs()
    result.d[key] = parseValue(p)

proc readNumberToken(p: var Parser): (string, bool) =
  ## Returns (token, isReal).
  var
    tok = ""
    isReal = false
  if p.pos < p.len and p.data[p.pos] in [byte('+'), byte('-')]:
    tok.add char(p.data[p.pos]); inc p.pos
  while p.pos < p.len:
    let b = p.data[p.pos]
    if char(b) in {'0'..'9'}:
      tok.add char(b); inc p.pos
    elif b == byte('.'):
      isReal = true; tok.add '.'; inc p.pos
    elif char(b) in {'e', 'E', '+', '-'} and isReal:
      tok.add char(b); inc p.pos
    else:
      break
  (tok, isReal)

proc parseNumberOrRef(p: var Parser): PdfObj =
  let (tok, isReal) = readNumberToken(p)
  if isReal or tok.len == 0:
    if tok.len == 0:                   # not actually a number; skip a byte
      inc p.pos
      return PdfObj(kind: pkNull)
    return PdfObj(kind: pkReal, rawf: tok)
  let num = parseInt(tok)
  # reference lookahead: "<int> <int> R"
  let save = p.pos
  p.skipWs()
  if p.pos < p.len and char(p.cur) in {'0'..'9'}:
    let (g, gReal) = readNumberToken(p)
    if not gReal and g.len > 0:
      let saveR = p.pos
      p.skipWs()
      if p.pos < p.len and p.cur == byte('R') and
         (p.pos + 1 >= p.len or not isRegular(p.data[p.pos + 1])):
        inc p.pos
        return PdfObj(kind: pkRef, rnum: num, rgen: parseInt(g))
      p.pos = saveR
  p.pos = save
  PdfObj(kind: pkInt, i: num)

proc parseValue*(p: var Parser): PdfObj =
  p.skipWs()
  if p.atEnd: return PdfObj(kind: pkNull)
  let b = p.cur
  case char(b)
  of '/': parseName(p)
  of '(': parseLiteralString(p)
  of '[': parseArray(p)
  of '<':
    if p.pos + 1 < p.len and p.data[p.pos+1] == byte('<'): parseDict(p)
    else: parseHexString(p)
  of '0'..'9', '+', '-', '.': parseNumberOrRef(p)
  of 't':
    if p.matches("true"):
      inc p.pos, 4; PdfObj(kind: pkBool, b: true)
    else:
      inc p.pos; PdfObj(kind: pkNull)
  of 'f':
    if p.matches("false"):
      inc p.pos, 5; PdfObj(kind: pkBool, b: false)
    else:
      inc p.pos; PdfObj(kind: pkNull)
  of 'n':
    if p.matches("null"):
      inc p.pos, 4; PdfObj(kind: pkNull)
    else:
      inc p.pos; PdfObj(kind: pkNull)
  else:
    inc p.pos
    PdfObj(kind: pkNull)

proc findKeyword(data: ptr UncheckedArray[byte], len, start: int, kw: string): int =
  ## Forward search for `kw`, returning its index or -1.
  let n = kw.len
  var i = start
  while i + n <= len:
    var ok = true
    for j in 0 ..< n:
      if data[i + j] != byte(kw[j]): ok = false; break
    if ok: return i
    inc i
  -1

proc dictGet*(o: PdfObj, key: string): PdfObj =
  if o == nil: return nil
  if o.kind == pkDict and o.d.hasKey(key): return o.d[key]
  if o.kind == pkStream and o.sd.hasKey(key): return o.sd[key]
  nil

proc parseIndirectBody(p: var Parser): PdfObj =
  ## Parse an object value, attaching stream data if a `stream` keyword follows.
  let val = parseValue(p)
  if val.kind != pkDict:
    return val
  let save = p.pos
  p.skipWs()
  if not p.matches("stream"):
    p.pos = save
    return val
  inc p.pos, 6                         # consume 'stream'
  if p.pos < p.len and p.data[p.pos] == 13'u8: inc p.pos
  if p.pos < p.len and p.data[p.pos] == 10'u8: inc p.pos
  let dataStart = p.pos
  # Prefer /Length if it is a sane integer, else search for endstream.
  var dataEnd = -1
  let lenObj = val.d.getOrDefault("Length", nil)
  if lenObj != nil and lenObj.kind == pkInt:
    let l = int(lenObj.i)
    if l >= 0 and dataStart + l <= p.len:
      var
        q = dataStart + l
        probe = q
      while probe < p.len and isWs(p.data[probe]): inc probe
      if probe + 9 <= p.len and findKeyword(p.data, probe + 9, probe, "endstream") == probe:
        dataEnd = q
  if dataEnd < 0:
    let es = findKeyword(p.data, p.len, dataStart, "endstream")
    if es < 0:
      dataEnd = p.len
      p.pos = p.len
    else:
      dataEnd = es
      # trim one trailing EOL that precedes 'endstream'
      if dataEnd > dataStart and p.data[dataEnd-1] == 10'u8: dec dataEnd
      if dataEnd > dataStart and p.data[dataEnd-1] == 13'u8: dec dataEnd
      p.pos = es
  else:
    p.pos = dataEnd
  var data = newSeq[byte](dataEnd - dataStart)
  for i in 0 ..< data.len: data[i] = p.data[dataStart + i]
  let es = findKeyword(p.data, p.len, p.pos, "endstream")
  if es >= 0: p.pos = es + 9
  result = PdfObj(kind: pkStream, sd: val.d, data: data)

# ---------------------------------------------------------------------------
# Whole-file scanning
# ---------------------------------------------------------------------------

proc scanObjects*(data: seq[byte]): seq[IndirectObj] =
  ## Find every `N G obj … endobj` by scanning for the `obj` keyword and
  ## reading the two integers before it. Later definitions of an object number
  ## override earlier ones (incremental updates).
  result = @[]
  let
    n = data.len
    dp = cast[ptr UncheckedArray[byte]](unsafeAddr data[0])
  var i = 0
  while i + 3 <= n:
    if dp[i] == byte('o') and dp[i+1] == byte('b') and dp[i+2] == byte('j') and
       (i == 0 or isWs(dp[i-1])) and
       (i + 3 >= n or not isRegular(dp[i+3])):
      # backtrack over: ws, gen digits, ws, num digits
      var j = i - 1
      while j >= 0 and isWs(dp[j]): dec j
      let genEnd = j
      while j >= 0 and char(dp[j]) in {'0'..'9'}: dec j
      let genStart = j + 1
      while j >= 0 and isWs(dp[j]): dec j
      let numEnd = j
      while j >= 0 and char(dp[j]) in {'0'..'9'}: dec j
      let numStart = j + 1
      if genStart <= genEnd and numStart <= numEnd:
        var numS = ""
        for k in numStart .. numEnd: numS.add char(dp[k])
        var genS = ""
        for k in genStart .. genEnd: genS.add char(dp[k])
        var p = initParser(data, i + 3)
        let value = parseIndirectBody(p)
        result.add IndirectObj(num: parseInt(numS), gen: parseInt(genS), value: value)
        i = max(i + 3, p.pos)
        continue
    inc i

proc scanTrailers*(data: seq[byte]): seq[PdfObj] =
  ## Parse every classic `trailer << … >>` dictionary, in file order.
  result = @[]
  let n = data.len
  var start = 0
  while true:
    let t = findKeyword(cast[ptr UncheckedArray[byte]](unsafeAddr data[0]), n, start, "trailer")
    if t < 0: break
    var p = initParser(data, t + 7)
    p.skipWs()
    if p.pos + 1 < p.len and p.cur == byte('<') and p.data[p.pos+1] == byte('<'):
      result.add parseDict(p)
    start = t + 7

# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

proc serialize*(o: PdfObj, outp: var seq[byte])

proc addStr(s: var seq[byte], str: string) =
  for c in str: s.add byte(c)

proc serializeName(name: string, outp: var seq[byte]) =
  outp.add byte('/')
  for c in name:
    let b = byte(c)
    if isRegular(b) and b > 32'u8 and c != '#':
      outp.add b
    else:
      addStr(outp, "#" & toHex(int(b), 2))

proc serializeHexStr(s: seq[byte], outp: var seq[byte]) =
  outp.add byte('<')
  for b in s: addStr(outp, toHex(int(b), 2))
  outp.add byte('>')

proc serializeDict(d: OrderedTable[string, PdfObj], outp: var seq[byte]) =
  addStr(outp, "<<")
  for k, v in d:
    serializeName(k, outp)
    outp.add byte(' ')
    serialize(v, outp)
    outp.add byte(' ')
  addStr(outp, ">>")

proc serialize*(o: PdfObj, outp: var seq[byte]) =
  if o == nil:
    addStr(outp, "null"); return
  case o.kind
  of pkNull: addStr(outp, "null")
  of pkBool: addStr(outp, if o.b: "true" else: "false")
  of pkInt: addStr(outp, $o.i)
  of pkReal: addStr(outp, o.rawf)
  of pkStr: serializeHexStr(o.s, outp)
  of pkName: serializeName(o.name, outp)
  of pkRef: addStr(outp, $o.rnum & " " & $o.rgen & " R")
  of pkArray:
    outp.add byte('[')
    for idx, item in o.arr:
      if idx > 0: outp.add byte(' ')
      serialize(item, outp)
    outp.add byte(']')
  of pkDict: serializeDict(o.d, outp)
  of pkStream:
    var d = o.sd
    d["Length"] = PdfObj(kind: pkInt, i: int64(o.data.len))
    serializeDict(d, outp)
    addStr(outp, "\nstream\n")
    for b in o.data: outp.add b
    addStr(outp, "\nendstream")
