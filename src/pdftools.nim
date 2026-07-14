# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## pdftools — a command-line toolbox for PDF files.
##
## Pure Nim, no third-party dependencies. The CLI is organised into
## subcommands (`pdftools <command> [options]`) so new tools can be added
## alongside the existing `unlock` command.

import
  std/[parseopt, os, terminal, strutils],
  pdf/writer,
  pdf/security,
  pdf/compress

const
  versionNumber = "0.1.0"
  gitHash = staticExec("git rev-parse --short HEAD").strip()
  version =
    "pdftools " & versionNumber &
    (if gitHash.len > 0: " (" & gitHash & ")" else: "")
  copyright = "Copyright (c) 2026 Advaita Saha. MIT License."

const banner = version & "\n" & copyright & "\n\n"

const topUsage = banner & """
pdftools — a pure-Nim, zero-dependency command-line toolbox for PDF files

Usage:
  pdftools <command> [options]

Commands:
  unlock    Decrypt (unlock) a password-protected PDF.
  compress  Losslessly shrink a PDF (Flate streams + object/xref streams).

Run 'pdftools <command> --help' for command-specific options.

Global:
  -h, --help       Show this help.
      --version    Show version.
"""

const unlockUsage = banner & """
pdftools unlock — decrypt a password-protected PDF

Usage:
  pdftools unlock [options] <input.pdf>

Options:
  -p, --password:<pw>     Password (user or owner). If omitted, you are prompted.
      --password-file:<f> Read the password from file <f> (first line, newline trimmed).
  -o, --out:<path>        Write to <path> instead of overwriting <input.pdf> in place.
      --keep-backup       Keep <input.pdf>.bak when overwriting in place.
  -h, --help              Show this help.

The unlocked PDF opens without a password. The original is overwritten in place
unless -o is given; the write is atomic (temp file + rename) so a wrong password
or error never corrupts the input.
"""

const compressUsage = """
pdftools compress — losslessly shrink a PDF

Usage:
  pdftools compress [options] <input.pdf>

Options:
  -o, --out:<path>        Write to <path> instead of overwriting <input.pdf> in place.
      --keep-backup       Keep <input.pdf>.bak when overwriting in place.
  -h, --help              Show this help.

Compression is lossless: every stream that is not already compressed is wrapped
in FlateDecode, small objects are packed into a compressed object stream, and the
cross-reference table is rebuilt as a compact /XRef stream. Text and vectors stay
byte-for-byte identical (no image re-sampling). Encrypted PDFs must be unlocked
first. The write is atomic (temp file + rename).
"""

proc readPasswordFile(path: string): string =
  let content = readFile(path)
  result = content
  if result.len > 0 and result[^1] == '\n': result.setLen(result.len - 1)
  if result.len > 0 and result[^1] == '\r': result.setLen(result.len - 1)

proc fail(msg: string) =
  stderr.writeLine("pdftools: " & msg)
  quit(1)

proc resolveOutPath(input, outPath: string): string =
  ## If -o names an existing directory, write into it using the input's
  ## basename (so `-o .` means "here"); otherwise use the path as given.
  result = outPath
  if outPath.len > 0 and dirExists(outPath):
    result = outPath / extractFilename(input)

proc writeOut(input, outPath: string, keepBackup: bool, bytes: seq[byte],
              doneMsg: string) =
  ## Shared output path: -o writes to a named file, otherwise overwrite the
  ## input atomically (temp file + rename), optionally keeping a .bak.
  try:
    if outPath.len > 0:
      writeFile(outPath, cast[string](bytes))
    else:
      let dir = parentDir(input)
      let tmp = (if dir.len > 0: dir else: ".") /
        ("." & extractFilename(input) & ".pdftools.tmp")
      writeFile(tmp, cast[string](bytes))
      if keepBackup:
        copyFile(input, input & ".bak")
      moveFile(tmp, input)
  except OSError, IOError:
    fail("could not write output: " & getCurrentExceptionMsg())
  stderr.writeLine("pdftools: " & doneMsg)

proc cmdUnlock(args: seq[string]) =
  var
    input = ""
    password = ""
    havePassword = false
    passwordFile = ""
    outPath = ""
    keepBackup = false

  # `pending` lets value options accept a space-separated argument
  # (`-p secret`) in addition to the attached form (`-p:secret`).
  var
    pending = ""
    p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdArgument:
      case pending
      of "password": password = key; havePassword = true
      of "password-file": passwordFile = key
      of "out": outPath = key
      else:
        if input.len == 0: input = key
        else: fail("unexpected extra argument: " & key)
      pending = ""
    of cmdShortOption, cmdLongOption:
      case key
      of "p", "password":
        if val.len > 0: (password = val; havePassword = true) else: pending = "password"
      of "password-file":
        if val.len > 0: passwordFile = val else: pending = "password-file"
      of "o", "out":
        if val.len > 0: outPath = val else: pending = "out"
      of "keep-backup": keepBackup = true
      of "h", "help": echo unlockUsage; quit(0)
      else: fail("unknown option: " & key)
    of cmdEnd: discard

  if input.len == 0:
    echo unlockUsage
    quit(1)
  if not fileExists(input):
    fail("input file not found: " & input)

  if passwordFile.len > 0:
    password = readPasswordFile(passwordFile)
    havePassword = true
  if not havePassword:
    if isatty(stdin):
      password = readPasswordFromStdin("Password: ")
    else:
      password = stdin.readLine()

  let data =
    try: cast[seq[byte]](readFile(input))
    except IOError as e: fail("could not read input: " & e.msg); @[]

  var res: UnlockResult
  try:
    res = unlock(data, password)
  except NotEncryptedError:
    fail(input & " is not encrypted; nothing to do.")
  except SecError as e:
    fail(e.msg & " (try the user or owner password)")
  except CatchableError as e:
    fail("failed to unlock: " & e.msg)

  var effOut = resolveOutPath(input, outPath)
  if effOut.len > 0 and absolutePath(effOut) == absolutePath(input):
    effOut = ""                              # writing over the input == in-place
  let owner = if res.usedOwnerPassword: " [owner password]" else: ""
  let doneMsg =
    if effOut.len > 0: "wrote unlocked PDF to " & effOut & owner
    else: "unlocked " & input & " in place" &
      (if keepBackup: " [backup at " & input & ".bak]" else: "") & owner
  writeOut(input, effOut, keepBackup, res.output, doneMsg)

proc cmdCompress(args: seq[string]) =
  var
    input = ""
    outPath = ""
    keepBackup = false
  var
    pending = ""
    p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdArgument:
      case pending
      of "out": outPath = key
      else:
        if input.len == 0: input = key
        else: fail("unexpected extra argument: " & key)
      pending = ""
    of cmdShortOption, cmdLongOption:
      case key
      of "o", "out":
        if val.len > 0: outPath = val else: pending = "out"
      of "keep-backup": keepBackup = true
      of "h", "help": echo compressUsage; quit(0)
      else: fail("unknown option: " & key)
    of cmdEnd: discard

  if input.len == 0:
    echo compressUsage
    quit(1)
  if not fileExists(input):
    fail("input file not found: " & input)

  let data =
    try: cast[seq[byte]](readFile(input))
    except IOError as e: fail("could not read input: " & e.msg); @[]

  var res: CompressResult
  try:
    res = compress(data)
  except EncryptedError as e:
    fail(e.msg)
  except CatchableError as e:
    fail("failed to compress: " & e.msg)

  # Never grow the file: if compression didn't help, keep the original bytes.
  let output = if res.compressedSize < res.originalSize: res.output else: data
  let saved = res.originalSize - output.len
  let pct =
    if res.originalSize > 0: formatFloat(saved / res.originalSize * 100, ffDecimal, 1)
    else: "0.0"
  var effOut = resolveOutPath(input, outPath)
  if effOut.len > 0 and absolutePath(effOut) == absolutePath(input):
    effOut = ""                              # writing over the input == in-place
  let where = if effOut.len > 0: "wrote " & effOut else: "compressed " & input & " in place"
  writeOut(input, effOut, keepBackup, output,
    where & ": " & $res.originalSize & " -> " & $output.len & " bytes (" &
    (if saved > 0: "-" & pct & "%" else: "no reduction") & ")" &
    (if keepBackup and effOut.len == 0: " [backup at " & input & ".bak]" else: ""))

proc main() =
  let params = commandLineParams()
  if params.len == 0:
    echo topUsage
    quit(1)

  let cmd = params[0]
  let rest = params[1 .. ^1]
  case cmd
  of "-h", "--help", "help": echo topUsage; quit(0)
  of "--version", "version": echo version; echo copyright; quit(0)
  of "unlock": cmdUnlock(rest)
  of "compress": cmdCompress(rest)
  else:
    stderr.writeLine("pdftools: unknown command '" & cmd & "'")
    echo topUsage
    quit(1)

when isMainModule:
  main()
