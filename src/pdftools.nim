# Copyright (c) 2026 Advaita Saha
# SPDX-License-Identifier: MIT

## pdftools — decrypt (unlock) a password-protected PDF.
##
## Pure Nim, no third-party dependencies. Supports the Standard Security
## Handler: RC4 (revisions 2-4), AES-128 (revision 4) and AES-256 (revision 6).

import
  std/[parseopt, os, terminal],
  pdf/writer,
  pdf/security

const usage = """
pdftools — unlock a password-protected PDF

Usage:
  pdftools [options] <input.pdf>

Options:
  -p, --password:<pw>     Password (user or owner). If omitted, you are prompted.
      --password-file:<f> Read the password from file <f> (first line, newline trimmed).
  -o, --out:<path>        Write to <path> instead of overwriting <input.pdf> in place.
      --keep-backup       Keep <input.pdf>.bak when overwriting in place.
  -h, --help              Show this help.
      --version           Show version.

The unlocked PDF opens without a password. The original is overwritten in place
unless -o is given; the write is atomic (temp file + rename) so a wrong password
or error never corrupts the input.
"""

proc readPasswordFile(path: string): string =
  let content = readFile(path)
  result = content
  if result.len > 0 and result[^1] == '\n': result.setLen(result.len - 1)
  if result.len > 0 and result[^1] == '\r': result.setLen(result.len - 1)

proc fail(msg: string) =
  stderr.writeLine("pdftools: " & msg)
  quit(1)

proc main() =
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
    p = initOptParser(commandLineParams())
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
      of "h", "help": echo usage; quit(0)
      of "version": echo "pdftools 0.1.0"; quit(0)
      else: fail("unknown option: " & key)
    of cmdEnd: discard

  if input.len == 0:
    echo usage
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

  if outPath.len > 0:
    writeFile(outPath, cast[string](res.output))
    stderr.writeLine("pdftools: wrote unlocked PDF to " & outPath &
      (if res.usedOwnerPassword: " (owner password)" else: ""))
  else:
    # Atomic in-place overwrite: write to a temp file then rename over the original.
    let dir = parentDir(input)
    let tmp = (if dir.len > 0: dir else: ".") / ("." & extractFilename(input) & ".pdftools.tmp")
    writeFile(tmp, cast[string](res.output))
    if keepBackup:
      copyFile(input, input & ".bak")
    moveFile(tmp, input)
    stderr.writeLine("pdftools: unlocked " & input & " in place" &
      (if keepBackup: " (backup at " & input & ".bak)" else: "") &
      (if res.usedOwnerPassword: " [owner password]" else: ""))

when isMainModule:
  main()
