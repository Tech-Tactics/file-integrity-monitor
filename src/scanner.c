/*
 * scanner.c
 * File Integrity Monitor - Scanner Module Implementation
 *
 * Recursively traverses directories, computes SHA-256 hashes
 * for each regular file, and collects metadata (size, permissions,
 * modification time) into FileRecord structs.
 *
 * Security considerations:
 *   - All string operations use bounded copies (strncpy/snprintf)
 *   - Path lengths are validated before concatenation
 *   - File reads use fixed-size buffers with explicit size checks
 *   - Memory is freed on all error paths to prevent leaks
 *   - Symbolic links are skipped to avoid traversal attacks
 *
 * Author: Joseph Black
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#include <openssl/evp.h>

#include "scanner.h"

/* Read buffer size for hashing - 8KB chunks */
#define READ_BUFFER_SIZE 8192

/* Initial capacity for the dynamic FileRecord array */
#define INITIAL_CAPACITY 128

/*
 * Internal: dynamic array management for FileRecord collection.
 * Grows by doubling when capacity is reached.
 */
typedef struct {
    FileRecord *data;
    int         count;
    int         capacity;
} RecordArray;

static int record_array_init(RecordArray *arr)
{
    arr->data = calloc(INITIAL_CAPACITY, sizeof(FileRecord));
    if (arr->data == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate record array\n");
        return -1;
    }
    arr->count = 0;
    arr->capacity = INITIAL_CAPACITY;
    return 0;
}

static int record_array_add(RecordArray *arr, const FileRecord *record)
{
    if (arr->count >= arr->capacity) {
        int new_capacity = arr->capacity * 2;
        FileRecord *new_data = realloc(arr->data,
                                       new_capacity * sizeof(FileRecord));
        if (new_data == NULL) {
            fprintf(stderr, "[ERROR] Failed to grow record array\n");
            return -1;
        }
        arr->data = new_data;
        arr->capacity = new_capacity;
    }
    arr->data[arr->count] = *record;
    arr->count++;
    return 0;
}

/*
 * get_file_permissions - Convert mode_t to a readable permission string.
 *
 * Produces output like "-rwxr-xr-x" following the ls -l convention.
 * The output buffer must be at least MAX_PERMS_LEN bytes.
 */
void get_file_permissions(unsigned int mode, char *output)
{
    if (output == NULL) {
        return;
    }

    output[0] = S_ISDIR(mode)  ? 'd' :
                S_ISLNK(mode)  ? 'l' :
                S_ISFIFO(mode) ? 'p' : '-';

    output[1] = (mode & S_IRUSR) ? 'r' : '-';
    output[2] = (mode & S_IWUSR) ? 'w' : '-';
    output[3] = (mode & S_IXUSR) ? 'x' : '-';
    output[4] = (mode & S_IRGRP) ? 'r' : '-';
    output[5] = (mode & S_IWGRP) ? 'w' : '-';
    output[6] = (mode & S_IXGRP) ? 'x' : '-';
    output[7] = (mode & S_IROTH) ? 'r' : '-';
    output[8] = (mode & S_IWOTH) ? 'w' : '-';
    output[9] = (mode & S_IXOTH) ? 'x' : '-';
    output[10] = '\0';
}

/*
 * compute_sha256 - Hash a file using OpenSSL EVP interface.
 *
 * Reads the file in 8KB chunks and feeds each chunk into
 * the digest context. The final hash is written as a 64-char
 * hex string. Uses EVP_MD_CTX for OpenSSL 1.1+ compatibility.
 *
 * Returns 0 on success, -1 on any failure.
 */
int compute_sha256(const char *file_path, char *output_hash)
{
    FILE          *fp = NULL;
    EVP_MD_CTX    *ctx = NULL;
    unsigned char  digest[EVP_MAX_MD_SIZE];
    unsigned int   digest_len = 0;
    unsigned char  buffer[READ_BUFFER_SIZE];
    size_t         bytes_read = 0;
    int            result = -1;

    if (file_path == NULL || output_hash == NULL) {
        return -1;
    }

    /* Open file in binary read mode */
    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[WARN] Cannot open file for hashing: %s (%s)\n",
                file_path, strerror(errno));
        return -1;
    }

    /* Create and initialize the digest context */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "[ERROR] Failed to create EVP_MD_CTX\n");
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "[ERROR] EVP_DigestInit_ex failed\n");
        goto cleanup;
    }

    /* Read and hash the file in chunks */
    while ((bytes_read = fread(buffer, 1, READ_BUFFER_SIZE, fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            fprintf(stderr, "[ERROR] EVP_DigestUpdate failed\n");
            goto cleanup;
        }
    }

    /* Check for read errors (as opposed to normal EOF) */
    if (ferror(fp)) {
        fprintf(stderr, "[WARN] Read error on file: %s\n", file_path);
        goto cleanup;
    }

    /* Finalize the hash */
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        fprintf(stderr, "[ERROR] EVP_DigestFinal_ex failed\n");
        goto cleanup;
    }

    /* Convert binary digest to hex string */
    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(output_hash + (i * 2), 3, "%02x", digest[i]);
    }
    output_hash[digest_len * 2] = '\0';
    result = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    fclose(fp);

    /* Zero out the digest buffer - defense in depth */
    memset(digest, 0, sizeof(digest));
    memset(buffer, 0, sizeof(buffer));

    return result;
}

/*
 * Internal: recursively walk a directory tree and collect FileRecords.
 *
 * Skips symbolic links to prevent directory traversal attacks.
 * Skips entries "." and ".." to prevent infinite loops.
 * Validates path length before concatenation to prevent overflow.
 */
static int walk_directory(const char *dir_path, RecordArray *arr,
                          int scan_id)
{
    DIR           *dir = NULL;
    struct dirent *entry = NULL;
    struct stat    file_stat;
    char           full_path[MAX_PATH_LEN];
    int            path_len = 0;

    dir = opendir(dir_path);
    if (dir == NULL) {
        fprintf(stderr, "[WARN] Cannot open directory: %s (%s)\n",
                dir_path, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. to prevent infinite recursion */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path with bounds check */
        path_len = snprintf(full_path, sizeof(full_path), "%s/%s",
                            dir_path, entry->d_name);
        if (path_len < 0 || (size_t)path_len >= sizeof(full_path)) {
            fprintf(stderr, "[WARN] Path too long, skipping: %s/%s\n",
                    dir_path, entry->d_name);
            continue;
        }

        /* Use lstat to detect symlinks - do not follow them */
        if (lstat(full_path, &file_stat) != 0) {
            fprintf(stderr, "[WARN] Cannot stat: %s (%s)\n",
                    full_path, strerror(errno));
            continue;
        }

        /* Skip symbolic links entirely */
        if (S_ISLNK(file_stat.st_mode)) {
            continue;
        }

        /* Recurse into subdirectories */
        if (S_ISDIR(file_stat.st_mode)) {
            walk_directory(full_path, arr, scan_id);
            continue;
        }

        /* Process regular files only */
        if (!S_ISREG(file_stat.st_mode)) {
            continue;
        }

        /* Build the FileRecord */
        FileRecord record;
        memset(&record, 0, sizeof(FileRecord));

        record.scan_id = scan_id;

        strncpy(record.file_path, full_path, MAX_PATH_LEN - 1);
        record.file_path[MAX_PATH_LEN - 1] = '\0';

        strncpy(record.file_name, entry->d_name, MAX_PATH_LEN - 1);
        record.file_name[MAX_PATH_LEN - 1] = '\0';

        record.file_size = (long)file_stat.st_size;

        /* Format modification time as ISO-8601 */
        struct tm *tm_info = localtime(&file_stat.st_mtime);
        if (tm_info != NULL) {
            strftime(record.last_modified, MAX_DETAIL_LEN,
                     "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(record.last_modified, "unknown", MAX_DETAIL_LEN - 1);
        }

        /* Get human-readable permissions */
        get_file_permissions(file_stat.st_mode, record.file_permissions);

        /* Compute SHA-256 hash */
        if (compute_sha256(full_path, record.sha256_hash) != 0) {
            strncpy(record.sha256_hash, "ERROR", MAX_HASH_LEN - 1);
        }

        /* Default status - will be updated by reporter during check */
        record.change_status = STATUS_BASELINE;
        record.change_class = CLASS_NONE;

        /* Add to the collection */
        if (record_array_add(arr, &record) != 0) {
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

/*
 * scan_directory - Public entry point for scanning.
 *
 * Validates the target path, initializes the record array,
 * walks the directory tree, and returns the results.
 * The caller must free the returned records array.
 */
int scan_directory(const char *target_path, FileRecord **records,
                   int *count, int scan_id)
{
    struct stat path_stat;
    RecordArray arr;

    if (target_path == NULL || records == NULL || count == NULL) {
        fprintf(stderr, "[ERROR] NULL parameter passed to scan_directory\n");
        return -1;
    }

    /* Verify the target path exists and is a directory */
    if (stat(target_path, &path_stat) != 0) {
        fprintf(stderr, "[ERROR] Target path does not exist: %s (%s)\n",
                target_path, strerror(errno));
        return -1;
    }

    if (!S_ISDIR(path_stat.st_mode)) {
        fprintf(stderr, "[ERROR] Target is not a directory: %s\n",
                target_path);
        return -1;
    }

    /* Initialize the dynamic array */
    if (record_array_init(&arr) != 0) {
        return -1;
    }

    /* Walk the directory tree */
    printf("[INFO] Scanning: %s\n", target_path);
    if (walk_directory(target_path, &arr, scan_id) != 0 && arr.count == 0) {
        free(arr.data);
        return -1;
    }

    printf("[INFO] Found %d files\n", arr.count);

    /* Transfer ownership to caller */
    *records = arr.data;
    *count = arr.count;

    return 0;
}
