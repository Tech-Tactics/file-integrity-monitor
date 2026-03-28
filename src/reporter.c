/*
 * reporter.c
 * File Integrity Monitor - Reporter Module Implementation
 *
 * Compares two scan sessions by matching file paths and hashes,
 * classifies changes as expected/unexpected/critical, and
 * produces color-coded terminal output.
 *
 * The comparison uses a hash-lookup approach: load the previous
 * scan's records into a simple lookup structure keyed by file_path,
 * then iterate the current scan and check each file against it.
 *
 * Author: Joseph Black
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reporter.h"
#include "database.h"

/* ANSI color codes for terminal output */
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RESET   "\033[0m"

/* Paths containing these substrings are classified as CRITICAL */
static const char *critical_paths[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/etc/pam.d/",
    ".conf",
    ".key",
    ".pem",
    NULL
};

/*
 * Internal: check if a file path matches any critical pattern.
 */
static int is_critical_path(const char *path)
{
    if (path == NULL) {
        return 0;
    }

    for (int i = 0; critical_paths[i] != NULL; i++) {
        if (strstr(path, critical_paths[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/*
 * Internal: find a file record in an array by file_path.
 *
 * Uses a simple linear scan. For very large directories, this
 * could be replaced with a hash table, but for typical use
 * (hundreds to low thousands of files) linear scan is adequate.
 */
static FileRecord *find_record_by_path(FileRecord *records, int count,
                                       const char *path)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(records[i].file_path, path) == 0) {
            return &records[i];
        }
    }
    return NULL;
}

/*
 * Internal: update a file record's status in the database.
 */
static int update_record_status(sqlite3 *db, int record_id,
                                ChangeStatus status, ChangeClass cls)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql =
        "UPDATE file_records SET change_status = ?, change_class = ? "
        "WHERE record_id = ?;";
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, status_to_string(status), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, class_to_string(cls), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, record_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/*
 * compare_scans - Main comparison logic.
 *
 * 1. Load both scan sessions from the database
 * 2. For each file in the current scan:
 *    - If not in previous scan -> NEW
 *    - If hash matches -> UNCHANGED
 *    - If hash differs -> MODIFIED
 * 3. For each file in previous scan not in current -> DELETED
 * 4. Classify MODIFIED/NEW/DELETED as CRITICAL or UNEXPECTED
 * 5. Update the database with the results
 */
int compare_scans(sqlite3 *db, int current_scan, int previous_scan,
                  ComparisonResult *result)
{
    FileRecord *current_records = NULL;
    FileRecord *previous_records = NULL;
    int         current_count = 0;
    int         previous_count = 0;

    if (db == NULL || result == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ComparisonResult));

    /* Load both scan sessions */
    if (db_get_file_records(db, current_scan,
                            &current_records, &current_count) != 0) {
        fprintf(stderr, "[ERROR] Failed to load current scan records\n");
        return -1;
    }

    if (db_get_file_records(db, previous_scan,
                            &previous_records, &previous_count) != 0) {
        fprintf(stderr, "[ERROR] Failed to load previous scan records\n");
        free(current_records);
        return -1;
    }

    result->total_current = current_count;
    result->total_previous = previous_count;

    printf("\n%s=== File Integrity Check ===%s\n\n", COLOR_BOLD, COLOR_RESET);

    /* Compare current files against previous baseline */
    for (int i = 0; i < current_count; i++) {
        FileRecord *curr = &current_records[i];
        FileRecord *prev = find_record_by_path(previous_records,
                                               previous_count,
                                               curr->file_path);

        ChangeStatus status;
        ChangeClass  cls;

        if (prev == NULL) {
            /* File exists now but didn't before */
            status = STATUS_NEW;
            cls = is_critical_path(curr->file_path)
                  ? CLASS_CRITICAL : CLASS_UNEXPECTED;
            result->new_files++;

            printf("  %s[NEW]%s %s\n", COLOR_GREEN, COLOR_RESET,
                   curr->file_path);

        } else if (strcmp(curr->sha256_hash, prev->sha256_hash) != 0) {
            /* File exists in both but hash changed */
            status = STATUS_MODIFIED;
            cls = is_critical_path(curr->file_path)
                  ? CLASS_CRITICAL : CLASS_UNEXPECTED;
            result->modified++;

            printf("  %s[MOD]%s %s\n", COLOR_YELLOW, COLOR_RESET,
                   curr->file_path);
            printf("        old: %.16s...\n", prev->sha256_hash);
            printf("        new: %.16s...\n", curr->sha256_hash);

            if (curr->file_size != prev->file_size) {
                printf("        size: %ld -> %ld bytes\n",
                       prev->file_size, curr->file_size);
            }

        } else {
            /* Hash matches - file is unchanged */
            status = STATUS_UNCHANGED;
            cls = CLASS_NONE;
            result->unchanged++;
            /* Don't print unchanged files - too noisy */
        }

        /* Track classification counts */
        switch (cls) {
            case CLASS_CRITICAL:   result->critical_changes++;   break;
            case CLASS_UNEXPECTED: result->unexpected_changes++; break;
            case CLASS_EXPECTED:   result->expected_changes++;   break;
            default: break;
        }

        /* Update the record in the database */
        curr->change_status = status;
        curr->change_class = cls;
        update_record_status(db, curr->record_id, status, cls);

        /* Mark the previous record as "seen" by zeroing its path */
        if (prev != NULL) {
            prev->file_path[0] = '\0';
        }
    }

    /* Find deleted files (in previous but not in current) */
    for (int i = 0; i < previous_count; i++) {
        if (previous_records[i].file_path[0] != '\0') {
            result->deleted++;

            ChangeClass cls = is_critical_path(previous_records[i].file_path)
                              ? CLASS_CRITICAL : CLASS_UNEXPECTED;

            if (cls == CLASS_CRITICAL)  result->critical_changes++;
            else                        result->unexpected_changes++;

            printf("  %s[DEL]%s %s\n", COLOR_RED, COLOR_RESET,
                   previous_records[i].file_path);
        }
    }

    printf("\n");

    free(current_records);
    free(previous_records);
    return 0;
}

/*
 * print_summary - Display a compact summary with color coding.
 */
void print_summary(const ComparisonResult *result)
{
    if (result == NULL) {
        return;
    }

    printf("%s--- Summary ---%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  Files in current scan:  %d\n", result->total_current);
    printf("  Files in baseline:      %d\n", result->total_previous);
    printf("  Unchanged:              %s%d%s\n",
           COLOR_GREEN, result->unchanged, COLOR_RESET);
    printf("  Modified:               %s%d%s\n",
           result->modified > 0 ? COLOR_YELLOW : "",
           result->modified,
           result->modified > 0 ? COLOR_RESET : "");
    printf("  New files:              %d\n", result->new_files);
    printf("  Deleted files:          %s%d%s\n",
           result->deleted > 0 ? COLOR_RED : "",
           result->deleted,
           result->deleted > 0 ? COLOR_RESET : "");

    printf("\n");

    if (result->critical_changes > 0) {
        printf("  %s%s!! CRITICAL CHANGES: %d !!%s\n",
               COLOR_BOLD, COLOR_RED,
               result->critical_changes, COLOR_RESET);
    }

    if (result->unexpected_changes > 0) {
        printf("  Unexpected changes:     %s%d%s\n",
               COLOR_YELLOW, result->unexpected_changes, COLOR_RESET);
    }

    if (result->critical_changes == 0 && result->unexpected_changes == 0 &&
        result->modified == 0 && result->new_files == 0 &&
        result->deleted == 0) {
        printf("  %sAll files match baseline - integrity verified.%s\n",
               COLOR_GREEN, COLOR_RESET);
    }

    printf("\n");
}

/*
 * print_report - Display the most recent check results.
 */
int print_report(sqlite3 *db, const char *target_path)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql =
        "SELECT fr.file_path, fr.change_status, fr.change_class, "
        "       fr.sha256_hash, fr.file_size "
        "FROM file_records fr "
        "JOIN scans s ON fr.scan_id = s.scan_id "
        "WHERE s.target_path = ? "
        "  AND fr.change_status != 'BASELINE' "
        "  AND fr.change_status != 'UNCHANGED' "
        "ORDER BY fr.change_class DESC, fr.change_status, fr.file_path;";
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Report query failed: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, target_path, -1, SQLITE_STATIC);

    printf("\n%s=== Integrity Report for: %s ===%s\n\n",
           COLOR_BOLD, target_path, COLOR_RESET);

    int rows = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *path   = (const char *)sqlite3_column_text(stmt, 0);
        const char *status = (const char *)sqlite3_column_text(stmt, 1);
        const char *cls    = (const char *)sqlite3_column_text(stmt, 2);
        const char *hash   = (const char *)sqlite3_column_text(stmt, 3);
        long        size   = (long)sqlite3_column_int64(stmt, 4);

        const char *color = COLOR_RESET;
        if (cls && strcmp(cls, "CRITICAL") == 0)       color = COLOR_RED;
        else if (status && strcmp(status, "MODIFIED") == 0) color = COLOR_YELLOW;
        else if (status && strcmp(status, "NEW") == 0)      color = COLOR_GREEN;
        else if (status && strcmp(status, "DELETED") == 0)  color = COLOR_RED;

        printf("  %s[%-10s] [%-10s]%s %s  (%ld bytes, %.16s...)\n",
               color, status ? status : "?", cls ? cls : "?",
               COLOR_RESET, path ? path : "?", size,
               hash ? hash : "?");
        rows++;
    }

    sqlite3_finalize(stmt);

    if (rows == 0) {
        printf("  %sNo changes detected in stored records.%s\n",
               COLOR_GREEN, COLOR_RESET);
    }

    printf("\n");
    return 0;
}
