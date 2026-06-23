# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## SHA-256 / SHA-384 / SHA-512 (FIPS 180-4) in pure Nim.
##
## Needed by the PDF revision-6 (AES-256 / PDF 2.0) key-derivation algorithm,
## which hashes with all three variants depending on intermediate state.

# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

const k256: array[64, uint32] = [
  0x428a2f98'u32,0x71374491'u32,0xb5c0fbcf'u32,0xe9b5dba5'u32,0x3956c25b'u32,0x59f111f1'u32,0x923f82a4'u32,0xab1c5ed5'u32,
  0xd807aa98'u32,0x12835b01'u32,0x243185be'u32,0x550c7dc3'u32,0x72be5d74'u32,0x80deb1fe'u32,0x9bdc06a7'u32,0xc19bf174'u32,
  0xe49b69c1'u32,0xefbe4786'u32,0x0fc19dc6'u32,0x240ca1cc'u32,0x2de92c6f'u32,0x4a7484aa'u32,0x5cb0a9dc'u32,0x76f988da'u32,
  0x983e5152'u32,0xa831c66d'u32,0xb00327c8'u32,0xbf597fc7'u32,0xc6e00bf3'u32,0xd5a79147'u32,0x06ca6351'u32,0x14292967'u32,
  0x27b70a85'u32,0x2e1b2138'u32,0x4d2c6dfc'u32,0x53380d13'u32,0x650a7354'u32,0x766a0abb'u32,0x81c2c92e'u32,0x92722c85'u32,
  0xa2bfe8a1'u32,0xa81a664b'u32,0xc24b8b70'u32,0xc76c51a3'u32,0xd192e819'u32,0xd6990624'u32,0xf40e3585'u32,0x106aa070'u32,
  0x19a4c116'u32,0x1e376c08'u32,0x2748774c'u32,0x34b0bcb5'u32,0x391c0cb3'u32,0x4ed8aa4a'u32,0x5b9cca4f'u32,0x682e6ff3'u32,
  0x748f82ee'u32,0x78a5636f'u32,0x84c87814'u32,0x8cc70208'u32,0x90befffa'u32,0xa4506ceb'u32,0xbef9a3f7'u32,0xc67178f2'u32]

proc rotr32(x: uint32, n: int): uint32 {.inline.} =
  (x shr n) or (x shl (32 - n))

proc sha256*(msg: openArray[byte]): seq[byte] =
  var h = [0x6a09e667'u32,0xbb67ae85'u32,0x3c6ef372'u32,0xa54ff53a'u32,
           0x510e527f'u32,0x9b05688c'u32,0x1f83d9ab'u32,0x5be0cd19'u32]
  # padding
  var data = newSeq[byte](msg.len)
  for i in 0 ..< msg.len: data[i] = msg[i]
  let bitLen = uint64(msg.len) * 8
  data.add 0x80'u8
  while data.len mod 64 != 56: data.add 0'u8
  for i in countdown(7, 0):
    data.add byte((bitLen shr (i * 8)) and 0xff)

  var
    w: array[64, uint32]
    off = 0
  while off < data.len:
    for t in 0 ..< 16:
      w[t] = (uint32(data[off + t*4]) shl 24) or (uint32(data[off + t*4+1]) shl 16) or
             (uint32(data[off + t*4+2]) shl 8) or uint32(data[off + t*4+3])
    for t in 16 ..< 64:
      let
        s0 = rotr32(w[t-15],7) xor rotr32(w[t-15],18) xor (w[t-15] shr 3)
        s1 = rotr32(w[t-2],17) xor rotr32(w[t-2],19) xor (w[t-2] shr 10)
      w[t] = w[t-16] + s0 + w[t-7] + s1
    var a=h[0]; var b=h[1]; var c=h[2]; var d=h[3]
    var e=h[4]; var f=h[5]; var g=h[6]; var hh=h[7]
    for t in 0 ..< 64:
      let
        S1 = rotr32(e,6) xor rotr32(e,11) xor rotr32(e,25)
        ch = (e and f) xor ((not e) and g)
        t1 = hh + S1 + ch + k256[t] + w[t]
        S0 = rotr32(a,2) xor rotr32(a,13) xor rotr32(a,22)
        maj = (a and b) xor (a and c) xor (b and c)
        t2 = S0 + maj
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh
    off += 64

  result = newSeq[byte](32)
  for i in 0 ..< 8:
    result[i*4]   = byte((h[i] shr 24) and 0xff)
    result[i*4+1] = byte((h[i] shr 16) and 0xff)
    result[i*4+2] = byte((h[i] shr 8) and 0xff)
    result[i*4+3] = byte(h[i] and 0xff)

# ---------------------------------------------------------------------------
# SHA-512 / SHA-384 (64-bit)
# ---------------------------------------------------------------------------

const k512: array[80, uint64] = [
  0x428a2f98d728ae22'u64,0x7137449123ef65cd'u64,0xb5c0fbcfec4d3b2f'u64,0xe9b5dba58189dbbc'u64,
  0x3956c25bf348b538'u64,0x59f111f1b605d019'u64,0x923f82a4af194f9b'u64,0xab1c5ed5da6d8118'u64,
  0xd807aa98a3030242'u64,0x12835b0145706fbe'u64,0x243185be4ee4b28c'u64,0x550c7dc3d5ffb4e2'u64,
  0x72be5d74f27b896f'u64,0x80deb1fe3b1696b1'u64,0x9bdc06a725c71235'u64,0xc19bf174cf692694'u64,
  0xe49b69c19ef14ad2'u64,0xefbe4786384f25e3'u64,0x0fc19dc68b8cd5b5'u64,0x240ca1cc77ac9c65'u64,
  0x2de92c6f592b0275'u64,0x4a7484aa6ea6e483'u64,0x5cb0a9dcbd41fbd4'u64,0x76f988da831153b5'u64,
  0x983e5152ee66dfab'u64,0xa831c66d2db43210'u64,0xb00327c898fb213f'u64,0xbf597fc7beef0ee4'u64,
  0xc6e00bf33da88fc2'u64,0xd5a79147930aa725'u64,0x06ca6351e003826f'u64,0x142929670a0e6e70'u64,
  0x27b70a8546d22ffc'u64,0x2e1b21385c26c926'u64,0x4d2c6dfc5ac42aed'u64,0x53380d139d95b3df'u64,
  0x650a73548baf63de'u64,0x766a0abb3c77b2a8'u64,0x81c2c92e47edaee6'u64,0x92722c851482353b'u64,
  0xa2bfe8a14cf10364'u64,0xa81a664bbc423001'u64,0xc24b8b70d0f89791'u64,0xc76c51a30654be30'u64,
  0xd192e819d6ef5218'u64,0xd69906245565a910'u64,0xf40e35855771202a'u64,0x106aa07032bbd1b8'u64,
  0x19a4c116b8d2d0c8'u64,0x1e376c085141ab53'u64,0x2748774cdf8eeb99'u64,0x34b0bcb5e19b48a8'u64,
  0x391c0cb3c5c95a63'u64,0x4ed8aa4ae3418acb'u64,0x5b9cca4f7763e373'u64,0x682e6ff3d6b2b8a3'u64,
  0x748f82ee5defb2fc'u64,0x78a5636f43172f60'u64,0x84c87814a1f0ab72'u64,0x8cc702081a6439ec'u64,
  0x90befffa23631e28'u64,0xa4506cebde82bde9'u64,0xbef9a3f7b2c67915'u64,0xc67178f2e372532b'u64,
  0xca273eceea26619c'u64,0xd186b8c721c0c207'u64,0xeada7dd6cde0eb1e'u64,0xf57d4f7fee6ed178'u64,
  0x06f067aa72176fba'u64,0x0a637dc5a2c898a6'u64,0x113f9804bef90dae'u64,0x1b710b35131c471b'u64,
  0x28db77f523047d84'u64,0x32caab7b40c72493'u64,0x3c9ebe0a15c9bebc'u64,0x431d67c49c100d4c'u64,
  0x4cc5d4becb3e42b6'u64,0x597f299cfc657e2a'u64,0x5fcb6fab3ad6faec'u64,0x6c44198c4a475817'u64]

proc rotr64(x: uint64, n: int): uint64 {.inline.} =
  (x shr n) or (x shl (64 - n))

proc sha512core(msg: openArray[byte], iv: array[8, uint64], outLen: int): seq[byte] =
  var h = iv
  var data = newSeq[byte](msg.len)
  for i in 0 ..< msg.len: data[i] = msg[i]
  let bitLen = uint64(msg.len) * 8   # 128-bit length field, but inputs are small
  data.add 0x80'u8
  while data.len mod 128 != 112: data.add 0'u8
  for _ in 0 ..< 8: data.add 0'u8   # high 64 bits of length (always 0 here)
  for i in countdown(7, 0):
    data.add byte((bitLen shr (i * 8)) and 0xff)

  var
    w: array[80, uint64]
    off = 0
  while off < data.len:
    for t in 0 ..< 16:
      var v: uint64 = 0
      for b in 0 ..< 8:
        v = (v shl 8) or uint64(data[off + t*8 + b])
      w[t] = v
    for t in 16 ..< 80:
      let
        s0 = rotr64(w[t-15],1) xor rotr64(w[t-15],8) xor (w[t-15] shr 7)
        s1 = rotr64(w[t-2],19) xor rotr64(w[t-2],61) xor (w[t-2] shr 6)
      w[t] = w[t-16] + s0 + w[t-7] + s1
    var a=h[0]; var b=h[1]; var c=h[2]; var d=h[3]
    var e=h[4]; var f=h[5]; var g=h[6]; var hh=h[7]
    for t in 0 ..< 80:
      let
        S1 = rotr64(e,14) xor rotr64(e,18) xor rotr64(e,41)
        ch = (e and f) xor ((not e) and g)
        t1 = hh + S1 + ch + k512[t] + w[t]
        S0 = rotr64(a,28) xor rotr64(a,34) xor rotr64(a,39)
        maj = (a and b) xor (a and c) xor (b and c)
        t2 = S0 + maj
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh
    off += 128

  var full = newSeq[byte](64)
  for i in 0 ..< 8:
    for b in 0 ..< 8:
      full[i*8 + b] = byte((h[i] shr ((7-b)*8)) and 0xff)
  full[0 ..< outLen]

proc sha512*(msg: openArray[byte]): seq[byte] =
  sha512core(msg, [0x6a09e667f3bcc908'u64,0xbb67ae8584caa73b'u64,0x3c6ef372fe94f82b'u64,
    0xa54ff53a5f1d36f1'u64,0x510e527fade682d1'u64,0x9b05688c2b3e6c1f'u64,0x1f83d9abfb41bd6b'u64,
    0x5be0cd19137e2179'u64], 64)

proc sha384*(msg: openArray[byte]): seq[byte] =
  sha512core(msg, [0xcbbb9d5dc1059ed8'u64,0x629a292a367cd507'u64,0x9159015a3070dd17'u64,
    0x152fecd8f70e5939'u64,0x67332667ffc00b31'u64,0x8eb44a8768581511'u64,0xdb0c2e0d64f98fa7'u64,
    0x47b5481dbefa4fa4'u64], 48)
