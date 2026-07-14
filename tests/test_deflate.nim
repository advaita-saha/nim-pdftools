# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## Round-trip tests for the DEFLATE encoder, verified against the inflate
## decoder (the two must be exact inverses).

import
  std/[strutils, random],
  unittest2,
  ../src/pdf/deflate,
  ../src/pdf/inflate

proc bytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc roundtrips(data: seq[byte]): bool =
  ## inflate(zlibCompress(x)) == x  AND  inflateRaw(deflate(x)) == x
  inflate(zlibCompress(data)) == data and inflateRaw(deflate(data)) == data

suite "deflate":
  test "empty and single byte":
    check roundtrips(@[])
    check roundtrips(@[65'u8])

  test "highly repetitive text":
    check roundtrips(bytes("Hello pdftools ".repeat(200)))
    check roundtrips(bytes("<< /Type /Page /Contents 5 0 R >>".repeat(300)))

  test "all-zero run (max compressible)":
    let zeros = newSeq[byte](10000)
    check roundtrips(zeros)
    # must actually shrink dramatically
    check zlibCompress(zeros).len < 200

  test "incompressible random data falls back to stored":
    var r = initRand(1234)
    var buf = newSeq[byte](4096)
    for i in 0 ..< buf.len: buf[i] = byte(r.rand(255))
    check roundtrips(buf)
    # stored-block overhead stays small (never blows up)
    check zlibCompress(buf).len < buf.len + 64

  test "compressible data is smaller":
    let data = bytes("the quick brown fox. ".repeat(100))
    check zlibCompress(data).len < data.len div 4

  test "all byte values present (literal coverage)":
    var buf = newSeq[byte](256 * 4)
    for i in 0 ..< buf.len: buf[i] = byte(i mod 256)
    check roundtrips(buf)
