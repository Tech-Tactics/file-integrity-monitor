/*
 * scanner.h
 * File Integrity Monitor - Scanner Module Interface
 *
 * Handles recursive directory traversal and SHA-256 hashing.
 * Uses OpenSSL EVP for cryptographic operations and POSIX
 * dirent/stat for filesystem access.
 *
 * Author: Joseph Black
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "fim_types.h"

/*
 * scan_directory - Recursively scan a directory tree.
 *
 * Walks the target path, computes SHA-256 for each regular file,
 * and populates an array of FileRecord structs. The caller is
 * responsible for freeing the returned array.
 *
 * Parameters:
 *   target_path  - absolute or relative path to scan
 *   records      - pointer to FileRecord array (allocated by function)
 *   count        - pointer to int, set to number of records found
 *   scan_id      - the scan session ID to tag each record with
 *
 * Returns:
 *   0 on success, -1 on failure (check errno)
 */
int scan_directory(const char *target_path, FileRecord **records,
                   int *count, int scan_id);

/*
 * compute_sha256 - Hash a single file.
 *
 * Reads the file in chunks and computes the SHA-256 digest.
 * The result is written as a 64-character hex string into output_hash.
 *
 * Parameters:
 *   file_path   - path to the file to hash
 *   output_hash - buffer of at least MAX_HASH_LEN bytes
 *
 * Returns:
 *   0 on success, -1 on failure
 */
int compute_sha256(const char *file_path, char *output_hash);

/*
 * get_file_permissions - Convert mode_t to human-readable string.
 *
 * Writes a string like "-rwxr-xr-x" into the output buffer.
 *
 * Parameters:
 *   mode   - file mode from stat()
 *   output - buffer of at least MAX_PERMS_LEN bytes
 */
void get_file_permissions(unsigned int mode, char *output);

#endif /* SCANNER_H */
