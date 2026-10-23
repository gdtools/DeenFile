# DeenFile
**Language**: 中文 | [English](README-en.md)

> A fast tool for hiding (encrypting) Windows files. It only stops "kids clicking around" — the cracking barrier is very low.
> Name origin: Decode Encode Files

## Features

- Extremely fast
- CLI support
- Trades crack-resistance for encode (hide) / decode (show) speed
- Priority: lossless restore > speed > crackability

## How It Works

A Windows directory masking tool: it hides directories (rename + CLSID suffix + hidden attribute), scrambles file names, and optionally scrambles file headers. **All transformations are reversible** — after a reinstall or moving to another machine, the same password restores everything completely.

## Commands

| Command | Password | Description |
|---|---|---|
| `deenfile` | No | Interactive menu |
| `deenfile add <dir>` | Yes | Register a directory (first use) |
| `deenfile encode` | No | Encrypt all registered directories |
| `deenfile decode [force]` | Yes | Decrypt all registered directories |
| `deenfile pwd` | Yes | Change password |
| `deenfile level [1\|2]` | No for query / Yes for change | Security level |
| `deenfile list` | Yes | List registered directories |

Interactive menu: `1 encode` / `2 decode` / `3 add` / `4 list` / `5 pwd` / `6 level` / `0 exit`

## Security Levels

| Level | Behavior | Speed |
|---|---|---|
| `1` (default) | Directory hiding + filename shift only, **never touches file contents** | Fast |
| `2` | All three layers, additionally scrambles file headers (first 1024 bytes XOR + 8-byte tail marker) | Slower |

- Stored in registry key `level`; defaults to 1 when absent
- `pwd` / `level` changes always **decrypt everything first**, write the registry only on success, then re-protect with the new setting; any failure aborts the whole operation — no half-finished state
- **Decoding is level-independent**: whether contents are touched is decided by the tail marker, so `decode` always restores everything correctly

## The Three Layers

1. **Directory hiding**: rename registered root directories with a CLSID suffix + hidden/system attributes
2. **Filename shift**: fixed offset within same-category character rings (CJK 7919 / letters 17 / digits 7), length strictly unchanged, files and directories treated alike
3. **Header scrambling**: only at level 2; files smaller than 1024 bytes are never touched

## Usage Notes

- During encode/decode, **do not cut power or kill the process** — wait for `ok` before touching anything
- **Never use `decode force`** (it damages unencrypted files)
- Keep `deenfile.exe` in its own directory — **do not put it inside a protected directory** (self-encryption breaks the exe)
- Do not place protected directories inside cloud-sync folders
- The password lives in the registry (obfuscated) — **forgetting it AND losing the registry = permanently destroyed file headers**. Remember it.

## Build

```bash
gcc -O2 -s -municode -o deenfile.exe deenfile.c
```

## Files

- `deenfile.c` — all source code (single file, no third-party dependencies)
- `deenfile开发文档.md` — detailed design doc (Chinese)
- `mkdata.py` / `verify.py` — test data generation and verification scripts
- `.github/workflows/release.yml` — GitHub Actions: auto build, package, and publish Releases
