# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## RC4 stream cipher (pure Nim).
##
## RC4 is symmetric: the same routine both encrypts and decrypts. PDF uses it
## for the V1/V2 crypt filters (revisions 2-4 of the Standard Security Handler).

proc rc4*(key, data: openArray[byte]): seq[byte] =
  ## Apply RC4 keyed by `key` to `data`, returning the transformed bytes.
  doAssert key.len > 0, "RC4 key must not be empty"
  var s: array[256, int]
  for i in 0 ..< 256:
    s[i] = i
  var j = 0
  for i in 0 ..< 256:
    j = (j + s[i] + int(key[i mod key.len])) and 0xff
    swap(s[i], s[j])

  result = newSeq[byte](data.len)
  var
    a = 0
    b = 0
  for n in 0 ..< data.len:
    a = (a + 1) and 0xff
    b = (b + s[a]) and 0xff
    swap(s[a], s[b])
    let k = s[(s[a] + s[b]) and 0xff]
    result[n] = data[n] xor byte(k)
