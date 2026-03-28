# File Integrity Monitor (FIM)

A command-line file integrity monitoring tool written in C. Scans directories, computes SHA-256 hashes for each file, and stores results in a SQLite database with full audit history. Detects modifications, additions, and deletions between scans and classifies changes by severity.

## Features

- **Recursive directory scanning** with SHA-256 hashing via OpenSSL
- **SQLite-backed audit history** — every scan is preserved, enabling comparison between any two points in time
- **Change classification** — changes are flagged as expected, unexpected, or critical based on file path patterns
- **Color-coded terminal output** — modified, new, and deleted files are highlighted for quick review
- **Audit logging** — every tool action records who ran it and when, supporting accountability requirements
- **Parameterized SQL queries** throughout — no string concatenation, aligned with OWASP and NIST secure coding practices
- **Safe C memory handling** — bounded string operations, NULL checks, and proper cleanup on all error paths

## Architecture

```
src/
├── main.c          CLI parsing and dispatch
├── scanner.c/.h    Directory traversal and SHA-256 hashing
├── database.c/.h   SQLite operations with parameterized queries
├── reporter.c/.h   Scan comparison, classification, and output
└── fim_types.h     Shared structs and enums
```

## Prerequisites

- GCC (or any C11-compatible compiler)
- OpenSSL development libraries (`libssl-dev`)
- SQLite3 development libraries (`libsqlite3-dev`)

### Install on Debian/Ubuntu

```bash
sudo apt-get install build-essential libssl-dev libsqlite3-dev
```

### Install on macOS

```bash
brew install openssl sqlite3
```

## Build

```bash
make            # Release build
make DEBUG=1    # Debug build with symbols
make clean      # Remove build artifacts
```

## Usage

```bash
# Create an initial baseline of a directory
./fim --baseline /etc

# Later, check for changes against the baseline
./fim --check /etc

# View stored change report
./fim --report /etc
```

### Example Output

```
[INFO] Scan session 2 started
[INFO] Scanning: ./test_dir
[INFO] Found 5 files
[INFO] Comparing scan 2 against baseline 1

=== File Integrity Check ===

  [MOD] ./test_dir/config.conf
        old: a1b2c3d4e5f6a7b8...
        new: 9f8e7d6c5b4a3928...
        size: 256 -> 312 bytes
  [NEW] ./test_dir/unauthorized.sh
  [DEL] ./test_dir/removed_file.txt

--- Summary ---
  Files in current scan:  5
  Files in baseline:      5
  Unchanged:              3
  Modified:               1
  New files:              1
  Deleted files:          1

  !! CRITICAL CHANGES: 1 !!
  Unexpected changes:     2
```

## Database Schema

The tool creates three tables:

- **scans** — session metadata (who, when, what path, mode)
- **file_records** — one row per file per scan (path, hash, size, permissions, status, classification)
- **audit_log** — every tool action for accountability

All queries use `sqlite3_prepare_v2` with parameter binding. No user input is ever concatenated into SQL strings.

## Security Design

This tool demonstrates several secure coding practices:

- **Input validation**: All paths and buffer sizes are checked before use
- **Bounded string operations**: `strncpy` and `snprintf` enforce limits
- **Symlink protection**: Symbolic links are skipped during traversal to prevent directory escape attacks
- **Memory safety**: Allocated memory is freed on all code paths including error branches
- **Parameterized queries**: SQL injection is structurally prevented
- **Audit trail**: NIST AU-12 aligned logging of all tool operations

## License

MIT
