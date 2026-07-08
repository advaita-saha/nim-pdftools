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
  pdf/security

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

proc readPasswordFile(path: string): string =
  let content = readFile(path)
  result = content
  if result.len > 0 and result[^1] == '\n': result.setLen(result.len - 1)
  if result.len > 0 and result[^1] == '\r': result.setLen(result.len - 1)

proc fail(msg: string) =
  stderr.writeLine("pdftools: " & msg)
  quit(1)

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
  else:
    stderr.writeLine("pdftools: unknown command '" & cmd & "'")
    echo topUsage
    quit(1)

when isMainModule:
  main()
