# pdftools

A command-line toolbox, written in **pure Nim with no third-party dependencies**,
for password-protected and oversized PDFs. It can **unlock** (decrypt) a PDF given
its password, and **compress** a PDF losslessly to a smaller file.

Every cryptographic and compression primitive it needs is implemented on top of
the Nim standard library alone — RC4, AES-128/256, SHA-256/384/512 and a DEFLATE
inflater *and deflater* are all hand-written; MD5 comes from `std/md5`.

## Build

```sh
nimble build      # produces ./build/pdftools
```

Requires Nim ≥ 2.0 (developed against 2.2.0). No packages are installed. The
compiled binary is written to `build/` (which is git-ignored).

## Usage

The CLI is organised into subcommands so more PDF tools can be added later:

```
pdftools <command> [options]

Commands:
  unlock    Decrypt (unlock) a password-protected PDF.
  compress  Losslessly shrink a PDF (Flate streams + object/xref streams).

Global:
  -h, --help     Show help.
      --version  Show version.
```

### `unlock`

```
pdftools unlock [options] <input.pdf>

  -p, --password:<pw>     Password (user or owner). If omitted, you are prompted.
      --password-file:<f> Read the password from file <f>.
  -o, --out:<path>        Write to <path> instead of overwriting in place.
      --keep-backup       Keep <input.pdf>.bak when overwriting in place.
  -h, --help              Show this command's help.
```

By default the input file is **overwritten in place** with the unlocked PDF. The
write is atomic — the decrypted output is written to a temporary file and renamed
over the original only on success — so a wrong password or any error never
corrupts the input. Use `-o` to write a separate file, or `--keep-backup` to keep
a `.bak` copy.

The password may be either the **user** password or the **owner** password; the
tool tries both. Many PDFs are "owner-locked" with an empty user password — in
that case just run without `-p` and press Enter at the prompt.

```sh
pdftools unlock -p 'secret' report.pdf            # overwrite report.pdf, unlocked
pdftools unlock -p 'secret' -o open.pdf report.pdf
```

### `compress`

```
pdftools compress [options] <input.pdf>

  -o, --out:<path>        Write to <path> instead of overwriting in place.
      --keep-backup       Keep <input.pdf>.bak when overwriting in place.
  -h, --help              Show this command's help.
```

Reduces file size **losslessly** — text and vectors stay byte-for-byte identical,
so there is no quality loss (images are *not* re-sampled or re-encoded). It does
three things:

- **(re)compresses stream data with DEFLATE.** Uncompressed streams are wrapped
  in `/FlateDecode`; streams that are *already* `/FlateDecode` are inflated and
  re-deflated with a stronger encoder (LZ77 + dynamic Huffman + lazy matching)
  and the smaller of the two is kept. Many PDFs ship weakly-compressed streams,
  so this alone often recovers 15–20%. Any `/DecodeParms` predictor is preserved
  (only the outer DEFLATE layer is swapped), and other filters such as
  `/DCTDecode` (JPEG) are never touched;
- packs the many small objects into a single compressed object stream
  (`/Type /ObjStm`);
- rebuilds the cross-reference table as a compact cross-reference stream
  (`/Type /XRef`).

Like `unlock`, it overwrites in place atomically by default; use `-o` or
`--keep-backup`. Encrypted PDFs must be unlocked first (compress refuses them and
tells you so). If compression would not shrink the file, the original bytes are
kept unchanged.

```sh
pdftools compress big.pdf                    # overwrite big.pdf, smaller
pdftools compress -o small.pdf big.pdf
pdftools unlock -p secret in.pdf && pdftools compress in.pdf   # unlock, then shrink
```

## Supported encryption

The PDF *Standard Security Handler*:

| Version / Revision        | Cipher       | Key derivation        |
|---------------------------|--------------|-----------------------|
| V1/V2, R2/R3              | RC4 (40-128) | MD5                   |
| V4, R4 (`V2`)             | RC4          | MD5                   |
| V4, R4 (`AESV2`)          | AES-128-CBC  | MD5                   |
| V5, R5 (deprecated draft) | AES-256-CBC  | SHA-256               |
| V5, R6 (PDF 2.0, `AESV3`) | AES-256-CBC  | SHA-256/384/512 (2.B) |

Both classic cross-reference tables and modern **cross-reference streams** are
handled, and **object streams** (`/Type /ObjStm`) are inflated and decomposed so
that compressed objects are recovered. The output is always written as a clean
single-revision PDF with a classic cross-reference table and no `/Encrypt` entry.

## Limitations

- The public-key handler (`/Filter /PubSec`, certificate-based) is not supported —
  it has no password.
- This is not a password cracker; you must supply the correct password.
- `unlock` output is uncompressed and may be larger than the input; run
  `compress` afterwards to shrink it again.
- `compress` is lossless only: it never re-encodes images (`/DCTDecode` etc.), so
  image-heavy PDFs shrink less than with a lossy optimiser.
- Object streams compressed with a predictor on `/DecodeParms` are uncommon and
  not handled.

## How it works

1. Scan the raw bytes for every `N G obj … endobj` indirect object (robust against
   broken cross-reference tables and incremental updates).
2. Read the trailer / cross-reference-stream dictionary (always plaintext) to find
   `/Encrypt`, `/Root`, `/ID`, `/Info`.
3. Derive the file key from the password and verify it against `/U` or `/O`.
4. Decrypt every object's strings and stream data with its per-object key; inflate
   and decompose object streams.
5. Re-serialize everything as a fresh, unencrypted, classic-xref PDF.

## Tests

```sh
nimble test
```

- `tests/test_crypto.nim` — known-answer vectors for RC4, AES-128/256 (FIPS-197),
  and SHA-256/384/512 (FIPS 180-4).
- `tests/test_pdf.nim` — end-to-end decryption of fixtures covering RC4-40/128,
  AES-128, AES-256 (R5 and R6), and modern object-stream PDFs, plus owner-password,
  wrong-password, object-stream-decomposition and not-encrypted cases.
- `tests/test_deflate.nim` — DEFLATE encoder round-trips, verified against the
  inflater (the two are exact inverses).
- `tests/test_compress.nim` — end-to-end `compress`, re-parsing the output and
  decoding the rebuilt `/XRef` stream to check every entry, plus idempotence and
  the encrypted-input refusal.

The fixtures in `tests/fixtures/` were produced with `pypdf` and `qpdf` from a
single base PDF.

## License

MIT — Copyright (c) 2026 Advaita Saha. See [LICENSE](LICENSE).
