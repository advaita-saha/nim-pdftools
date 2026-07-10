<!--
Copyright (c) 2026 Advaita Saha
SPDX-License-Identifier: MIT
-->

# How pdftools unlocks a PDF

This document explains, end to end, how PDF password protection works and how
`pdftools` removes it. It covers the file format, the cryptography, the exact
algorithms implemented, and how each module of the code fits together.

> **Scope.** `pdftools` decrypts a PDF when you already know the password (the
> user or the owner password). It is not a password cracker.

---

## 1. The big picture

A "locked" PDF is not scrambled as one opaque blob. The structure of the file —
the catalog, the page tree, object boundaries, the cross-reference table — stays
in **plaintext**. What is encrypted is the *content*: every **string** and every
**stream** (page content, fonts, images, metadata, …).

To unlock a PDF you therefore need to:

1. Find the recipe the file used to encrypt itself (the **`/Encrypt`**
   dictionary).
2. Turn the password into the **file encryption key**, and check it's correct.
3. Walk every object and **decrypt its strings and streams** with the right
   per-object key and cipher.
4. Write the objects back out **without** the `/Encrypt` entry, so no reader ever
   tries to decrypt again.

That's exactly the pipeline in [`src/pdf/writer.nim`](../src/pdf/writer.nim)'s
`unlock` proc. The rest of this document fills in the details.

---

## 2. Anatomy of a PDF (just enough)

A PDF is a sequence of **indirect objects**:

```
12 0 obj
<< /Type /Page /Contents 13 0 R >>
endobj
```

`12` is the object number, `0` is the generation number. Objects can be:

- numbers, booleans, `null`
- **names** like `/Type`
- **strings** — literal `(Hello)` or hex `<48656C6C6F>`
- **arrays** `[ … ]` and **dictionaries** `<< … >>`
- **references** `13 0 R` (a pointer to object 13)
- **streams** — a dictionary followed by raw bytes between `stream` … `endstream`

At the very end of the file is the **trailer**, which names the document root and
(if encrypted) points at the encryption dictionary:

```
trailer
<< /Root 1 0 R /Info 6 0 R /Encrypt 9 0 R
   /ID [<a1b2…> <c3d4…>] >>
startxref
54213
%%EOF
```

Two trailer entries matter for decryption:

- **`/Encrypt`** — a reference to the dictionary describing the encryption.
- **`/ID`** — a pair of byte strings identifying the file. The *first* element,
  `ID[0]`, is mixed into the key derivation (so the same password produces
  different keys for different files).

> Modern PDFs (1.5+) may store objects packed inside **object streams**
> (`/Type /ObjStm`) and the cross-reference table as a **cross-reference stream**
> (`/Type /XRef`). We handle both — see §8.

---

## 3. The `/Encrypt` dictionary

This dictionary is **never encrypted** (otherwise you couldn't bootstrap
decryption). A typical one:

```
9 0 obj
<< /Filter /Standard      % the standard password handler
   /V 5  /R 6              % algorithm version / revision
   /Length 256            % key length in bits
   /O (…32 or 48 bytes…)   % owner-password verification data
   /U (…32 or 48 bytes…)   % user-password verification data
   /OE (…) /UE (…)        % (R6 only) encrypted file keys
   /P -3392               % permission flags (signed int)
   /CF << /StdCF << /CFM /AESV3 >> >>   % crypt filters (V≥4)
   /StmF /StdCF /StrF /StdCF >>
endobj
```

The fields that drive everything:

| Field      | Meaning |
|------------|---------|
| `/Filter`  | Must be `/Standard`. (Certificate-based `/PubSec` is out of scope — no password.) |
| `/V`, `/R` | Which key-derivation algorithm and cipher to use. |
| `/Length`  | Key length in bits (40–256). |
| `/O`, `/U` | Verification data derived from the owner / user passwords. |
| `/P`       | Permission bits (also mixed into the key for R2–R4). |
| `/CF`, `/StmF`, `/StrF` | (V≥4) which cipher encrypts **streams** vs **strings** — RC4, AES, or `Identity` (= not encrypted). |
| `/OE`, `/UE` | (R6) AES-wrapped copies of the file key. |

The combination of `/V` and `/R` selects one of three worlds:

| V / R                  | Cipher      | Key derivation        | Key length |
|------------------------|-------------|-----------------------|-----------|
| V1/V2, R2/R3           | RC4         | MD5                   | 40–128 bit |
| V4, R4 `V2`/`AESV2`    | RC4 / AES   | MD5                   | 128 bit |
| V5, R5 (legacy draft)  | AES         | SHA-256               | 256 bit |
| V5, R6 (PDF 2.0)       | AES         | SHA-256/384/512 (2.B) | 256 bit |

---

## 4. How a PDF gets *locked*

Understanding locking makes unlocking obvious — they're mirror images.

A writer that encrypts a PDF does this:

1. **Generate a file key.** For RC4/AES-128 (R2–R4) the key is *derived* from the
   user password. For AES-256 (R5/R6) a random 32-byte key is generated and then
   *wrapped* (encrypted) under a key derived from the password.
2. **Store verification data.** It computes `/U` (and `/O`) so that, later, a
   reader can confirm a candidate password reproduces the same value. For R6 it
   also stores `/UE` / `/OE`: the file key encrypted under the password-derived
   key.
3. **Encrypt every string and stream.** Each object gets a **per-object key**
   (R2–R4) or uses the file key directly (R5/R6). Strings and stream bytes are
   replaced by their ciphertext. AES additionally prepends a random 16-byte IV
   and pads to a 16-byte boundary.
4. **Write the `/Encrypt` dictionary** into the file and reference it from the
   trailer.

Unlocking reverses steps 3 → 1: recover the file key from the password, decrypt
every string/stream, then drop `/Encrypt`.

---

## 5. From password to file key

This is the heart of the matter. There are two algorithm families, both in
[`src/pdf/security.nim`](../src/pdf/security.nim).

### 5.1 The padding string

PDF passwords are always normalised to exactly 32 bytes: take the password bytes,
truncate to 32, and if shorter, append from a fixed 32-byte **padding string**
(`0x28 0xBF 0x4E 0x5E …`). This is `padPassword` in the code.

### 5.2 RC4 and AES-128 (revisions 2–4) — *Algorithm 2*

```
key = MD5( paddedPassword
           ‖ O                       (32 bytes)
           ‖ P as 4 little-endian bytes
           ‖ ID[0]
           ‖ 0xFFFFFFFF if (R≥4 and EncryptMetadata is false) )

if R ≥ 3:
    repeat 50 times:  key = MD5(key[0 .. n-1])

fileKey = key[0 .. n-1]     where n = /Length / 8
```

So the key depends on the password **and** the file's `/O`, `/P`, and `/ID[0]`.
This is `fileKeyFromPadded`.

### 5.3 Per-object keys — *Algorithm 1*

In R2–R4 each object is encrypted with its *own* key, derived from the file key
plus the object's number and generation:

```
objKey = MD5( fileKey
              ‖ objNum  (low 3 bytes, little-endian)
              ‖ objGen  (low 2 bytes, little-endian)
              ‖ "sAlT"  (only for AES) )

objKey = objKey[0 .. min(n+5, 16) - 1]
```

This is `objectKey`. Why per-object? So that identical plaintext in two different
objects doesn't produce identical ciphertext, without needing a random IV (RC4 is
a stream cipher and has no IV).

### 5.4 AES-256 (revisions 5 and 6)

Here `/U` and `/O` are **48 bytes**: `hash(32) ‖ validationSalt(8) ‖ keySalt(8)`.

```
# user password
if HASH(password ‖ U.validationSalt) == U.hash:        # password is correct
    ik      = HASH(password ‖ U.keySalt)
    fileKey = AES-256-CBC-decrypt(UE, key = ik, iv = 0, no padding)
```

The owner-password path is analogous but folds in the full 48-byte `/U` value and
decrypts `/OE`.

`HASH` differs by revision (this is the one subtlety between R5 and R6):

- **R5** (a deprecated Adobe draft): `HASH = SHA-256` once.
- **R6** (PDF 2.0): `HASH` is the hardened, iterated **Algorithm 2.B** —
  `hash2B` in the code:

```
K = SHA-256(password ‖ salt ‖ udata)
round = 0
repeat:
    K1 = (password ‖ K ‖ udata) repeated 64 times
    E  = AES-128-CBC-encrypt(K1, key = K[0..15], iv = K[16..31])
    K  = SHA-256 / SHA-384 / SHA-512 (E)   # chosen by (sum of E[0..15]) mod 3
    round += 1
until round ≥ 64 and E[last] ≤ round - 32
return K[0..31]
```

This deliberately costs many hash + AES operations to slow down brute force. It is
why a pure-Nim build needs SHA-256, SHA-384 **and** SHA-512, plus AES-128
encryption.

### 5.5 Verifying the password

We never "just try" the key — we confirm it:

- **R2:** `/U` should equal `RC4(fileKey, paddingString)` (*Algorithm 4*).
- **R3/R4:** `/U[0..15]` should equal a 20-step RC4 cascade over
  `MD5(padding ‖ ID[0])` (*Algorithm 5*). This is `computeU`.
- **R5/R6:** the salted hash comparison shown above.

If the password fails as a *user* password, we retry it as an *owner* password:
for R2–R4 we recover the padded user password out of `/O`
(`userPaddedFromOwner`), then derive and verify the key as usual. If both fail,
`setupSecurity` raises `SecError` ("incorrect password") and — crucially — the
original file is never touched.

---

## 6. The cipher / compression primitives we implemented

Everything below is hand-written in pure Nim so the project has **zero
third-party dependencies**. MD5 is the only one taken from the standard library
(`std/md5`).

### RC4 — [`src/crypto/rc4.nim`](../src/crypto/rc4.nim)
A ~20-line stream cipher: a 256-byte state array is key-scheduled (KSA), then a
keystream is generated (PRGA) and XORed with the data. Symmetric — the same proc
encrypts and decrypts.

### AES — [`src/crypto/aes.nim`](../src/crypto/aes.nim)
Textbook FIPS-197 implementation supporting 128/192/256-bit keys: S-box and
inverse S-box tables, GF(2⁸) multiplication for `MixColumns`, key expansion, and
single-block encrypt/decrypt. On top of that, **CBC** mode (`aesCbcDecrypt`,
`aesCbcEncryptRaw`) and **PKCS#7** unpadding (`pkcs7Unpad`).

### SHA-2 — [`src/crypto/sha2.nim`](../src/crypto/sha2.nim)
SHA-256 (32-bit words, 64 rounds) and SHA-384/512 (64-bit words, 80 rounds),
needed only by the R6 key derivation.

### DEFLATE inflate — [`src/pdf/inflate.nim`](../src/pdf/inflate.nim)
A from-scratch RFC 1951 decompressor (stored / fixed-Huffman / dynamic-Huffman
blocks) with RFC 1950 zlib-header detection. Used **only** to unpack object
streams (see §8). Note we never *re*-compress: ordinary content streams are
decrypted while staying compressed.

All of these are checked against published test vectors in
[`tests/test_crypto.nim`](../tests/test_crypto.nim).

---

## 7. Decrypting a string vs a stream

Once we have the file key, decrypting one piece of data
(`decryptStream` / `decryptString` in `security.nim`) dispatches on the crypt
method:

- **Identity** → return the bytes unchanged (the filter explicitly says "not
  encrypted").
- **RC4** → `RC4(objectKey, data)`.
- **AES-128 (AESV2)** → `data[0..15]` is the IV; CBC-decrypt the rest with the
  per-object key, then strip PKCS#7 padding.
- **AES-256 (AESV3)** → same, but the key is the 32-byte file key directly (no
  per-object key).

Two important exemptions are honoured during the walk:

- The **`/Encrypt` dictionary** itself and the trailer **`/ID`** are plaintext —
  we never decrypt them.
- A **`/Metadata`** stream is left alone when the file set
  `/EncryptMetadata false`.

> **Why AES changes object sizes.** AES decryption removes the 16-byte IV and the
> padding, so a decrypted stream is *shorter* than its ciphertext. That means we
> cannot patch bytes in place — every object's `/Length` and the byte offsets
> shift. This is the main reason the tool fully re-serializes the file rather than
> editing it (see §9).

---

## 8. Object streams and cross-reference streams

In PDF 1.5+ many objects are not written as `N G obj … endobj`. Instead they are
**packed**, concatenated, and FlateDecode-compressed inside a single
`/Type /ObjStm` stream, and the cross-reference table itself becomes a compressed
`/Type /XRef` stream.

`pdftools` handles this without needing the xref at all:

- **Finding the trailer info.** The `/Root`, `/Encrypt`, `/ID`, `/Info` keys live
  in the *dictionary* of the XRef stream, which is plaintext — so we read them
  directly (`collectTrailer`) and never have to decompress the xref.
- **Recovering packed objects.** We decrypt the ObjStm's stream bytes, `inflate`
  them, then split them using the stream's `/N` (object count) and `/First`
  (offset of the first object) header (`decomposeObjStm`). The objects *inside* an
  ObjStm are **not** individually encrypted — decrypting the container is enough —
  so the extracted objects are emitted as ordinary indirect objects.

The output always uses a plain classic xref table, so the result opens in any
reader regardless of how the input was structured.

---

## 9. How our code is organised

```
src/
  pdftools.nim        CLI: subcommand dispatch, the `unlock` command, atomic write
  crypto/
    rc4.nim           RC4
    aes.nim           AES-128/192/256 + CBC + PKCS#7
    sha2.nim          SHA-256/384/512
  pdf/
    inflate.nim       DEFLATE/zlib inflate (for object streams)
    objects.nim       PDF value model: parser, whole-file scanner, serializer
    security.nim      Standard Security Handler: key derivation + decryption
    writer.nim        Orchestration: unlock() — decrypt everything & rebuild
```

### The pipeline (`writer.nim` → `unlock`)

1. **`scanObjects(data)`** — scan the raw bytes for every `N G obj … endobj`. We
   deliberately do *not* trust the cross-reference table; scanning is robust
   against broken xrefs and incremental updates (later definitions of an object
   number win). Each object's body is parsed by `objects.nim`'s `parseValue` /
   `parseIndirectBody`.
2. **`collectTrailer`** — gather `/Root`, `/Encrypt`, `/ID`, `/Info`, `/Size` from
   the classic `trailer` dictionaries and/or XRef-stream dicts.
3. If there is no `/Encrypt`, raise `NotEncryptedError` (nothing to do).
4. **`setupSecurity(encDict, ID[0], password)`** — derive and verify the file key
   (§5). Raises `SecError` on a wrong password.
5. **Walk every object:**
   - `decryptStrings` recurses through dictionaries/arrays/stream dicts and
     decrypts each string with the object's number/gen.
   - stream bytes are decrypted (unless exempt).
   - `/Type /XRef` objects are dropped (we rebuild the xref).
   - `/Type /ObjStm` objects are inflated, decomposed, and replaced by their
     contents.
6. **Re-serialize.** `objects.nim`'s `serialize` writes each value back in
   canonical form (strings are emitted as hex, which is always valid and avoids
   escaping bugs; stream `/Length` is recomputed from the decrypted bytes). The
   writer emits a fresh `%PDF` header, every object with new offsets, a brand-new
   classic `xref` table, and a trailer that keeps `/Root`, `/Info`, `/ID` but
   **omits `/Encrypt`**.

The result is a clean, single-revision, unencrypted PDF.

### The CLI (`pdftools.nim`)

`main()` reads the first argument as a **subcommand** and dispatches
(`pdftools <command> …`), so new tools can be added next to `unlock`. The
`unlock` command parses its own options, reads the password (from `-p`, a file,
or an interactive no-echo prompt), calls `unlock`, and writes the result.

By default it **overwrites the input in place**, but safely: the decrypted bytes
are written to a temporary file and only `moveFile`-renamed over the original on
success. A wrong password aborts before any write, so the original is never
corrupted. `-o` writes to a separate path instead; `--keep-backup` keeps a `.bak`.

---

## 10. Why scan-and-rebuild instead of patch-in-place?

- **AES changes lengths** (§7), so offsets shift and a byte patch is impossible
  anyway.
- **Robustness:** scanning tolerates damaged cross-reference tables, linearized
  files, and incremental updates.
- **Simplicity of output:** collapsing object streams and xref streams into one
  classic-xref revision produces a file that every reader accepts, instead of
  trying to faithfully reproduce (and re-encrypt-strip) the original layout.

---

## 11. Limitations

- The certificate-based public-key handler (`/Filter /PubSec`) is unsupported — it
  is not password-based.
- This is a decryptor, not a cracker: the correct password is required.
- Streams are not recompressed, so the output may be larger than the input.
- Object streams compressed with a `/DecodeParms` predictor (uncommon) are not
  handled.

---

## 12. Further reading

- ISO 32000-1 / 32000-2 (the PDF specification), §7 "Syntax" and the encryption
  sections — the source of the algorithm numbers referenced above.
- FIPS-197 (AES), FIPS 180-4 (SHA-2), RFC 1320 (MD5), RFC 1951 (DEFLATE),
  RFC 1950 (zlib).
