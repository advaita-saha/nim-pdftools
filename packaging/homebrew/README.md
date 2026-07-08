# Homebrew packaging

`pdftools` is distributed for Homebrew as **pre-built binaries** through a personal tap.
The `Release` workflow (`.github/workflows/release.yml`) builds and drafts a release on a
tag push, then updates the tap formula when you publish that draft. These are the one-time
bootstrap steps.

## One-time setup

1. **Create the tap repo.** Make an empty public repo named exactly
   **`advaita-saha/homebrew-tap`** (the `homebrew-` prefix is required; it maps to
   `brew tap advaita-saha/tap`). No files needed — the release workflow creates
   `Formula/pdftools.rb` on the first release.

2. **Create a token for the workflow to push to the tap.** Generate a fine-grained
   Personal Access Token scoped to `advaita-saha/homebrew-tap` with **Contents:
   read/write**, then add it to *this* repo as a secret named **`TAP_GITHUB_TOKEN`**
   (Settings → Secrets and variables → Actions).

## Cutting a release (two phases)

**1. Push a tag** — builds the binaries and creates a **draft** GitHub Release:

```sh
git tag v0.1.0
git push origin v0.1.0
```

This builds `pdftools` for macos-arm64, linux-amd64, linux-arm64, and windows-amd64,
attaches `pdftools-<version>-<os>-<arch>.tar.gz` (Windows ships as a `.zip`), and writes
the SHA-256 checksums into the release notes.

**2. Publish the draft** — review it in the GitHub UI and click **Publish release**. That
fires the `release: published` event, which renders `pdftools.rb.tmpl` with the real
checksums and pushes `Formula/pdftools.rb` to the tap.

The formula update is gated on *publish* on purpose: a draft release's assets are not
served from the public `releases/download/...` URLs, so the formula must only point at
them once the release is live.

The Windows build is a direct-download release asset only — Homebrew is macOS/Linux, so
Windows is not part of the formula.

## Install (end users)

```sh
brew install advaita-saha/tap/pdftools
```

## Files
- `pdftools.rb.tmpl` — Homebrew formula template; `${VERSION}` and `${SHA_*}` are filled
  by `envsubst` in the workflow. Edit the formula here (desc/homepage/test), not in the tap
  repo, since the tap copy is overwritten on every release.
