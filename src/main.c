/*
 * main.c
 * File Integrity Monitor - Entry Point
 *
 * Parses command-line arguments and dispatches to the appropriate
 * module. Keeps main thin - all logic lives in the modules.
 *
 * Usage:
 *   fim --baseline <directory>     First scan, create the baseline
 *   fim --check <directory>        Compare current state to baseline
 *   fim --report <directory>       Show stored comparison results
 *   fim --help                     Display usage information
 *
 * Author: Joseph Black
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "fim_types.h"
#include "scanner.h"
#include "database.h"
#include "reporter.h"

#define FIM_DB_FILE "fim_data.db"
#define FIM_VERSION "1.0.0"

/*
 * get_current_user - Retrieve the username of whoever runs the tool.
 *
 * Used for audit logging. Falls back to "unknown" if lookup fails.
 */
static void get_current_user(char *buffer, size_t len)
{
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL) {
        strncpy(buffer, pw->pw_name, len - 1);
        buffer[len - 1] = '\0';
    } else {
        strncpy(buffer, "unknown", len - 1);
        buffer[len - 1] = '\0';
    }
}

static void print_usage(void)
{
    printf("\n");
    printf("File Integrity Monitor (FIM) v%s\n", FIM_VERSION);
    printf("=========================================\n\n");
    printf("Usage:\n");
    printf("  fim --baseline <directory>   Create initial file hash baseline\n");
    printf("  fim --check <directory>      Check current state against baseline\n");
    printf("  fim --report <directory>     View stored integrity report\n");
    printf("  fim --help                   Show this help message\n");
    printf("\nExamples:\n");
    printf("  fim --baseline /etc          Baseline the /etc directory\n");
    printf("  fim --check /etc             Check /etc for changes\n");
    printf("  fim --report /etc            View change report for /etc\n");
    printf("\n");
}

/*
 * run_baseline - Scan a directory and store the initial baseline.
 */
static int run_baseline(sqlite3 *db, const char *target_path,
                        const char *user)
{
    ScanSession  session;
    FileRecord  *records = NULL;
    int          count = 0;
    char         detail[MAX_DETAIL_LEN];

    memset(&session, 0, sizeof(ScanSession));
    session.scan_mode = MODE_BASELINE;
    strncpy(session.target_path, target_path, MAX_PATH_LEN - 1);
    strncpy(session.run_by_user, user, MAX_USER_LEN - 1);

    /* Create the scan session record */
    if (db_insert_scan(db, &session) != 0) {
        fprintf(stderr, "[ERROR] Failed to create scan session\n");
        return -1;
    }

    printf("[INFO] Scan session %d started\n", session.scan_id);

    /* Scan the directory tree */
    if (scan_directory(target_path, &records, &count, session.scan_id) != 0) {
        fprintf(stderr, "[ERROR] Directory scan failed\n");
        return -1;
    }

    /* Store all records in a single transaction */
    if (db_insert_file_records_batch(db, records, count) != 0) {
        fprintf(stderr, "[ERROR] Failed to store file records\n");
        free(records);
        return -1;
    }

    /* Update scan totals */
    db_update_scan_totals(db, session.scan_id, count, 0);

    /* Write audit log entry */
    snprintf(detail, sizeof(detail),
             "Baseline scan of %s: %d files recorded", target_path, count);
    db_write_audit_log(db, "BASELINE", user, detail);

    printf("[INFO] Baseline complete: %d files stored in scan %d\n",
           count, session.scan_id);

    free(records);
    return 0;
}

/*
 * run_check - Scan and compare against the stored baseline.
 */
static int run_check(sqlite3 *db, const char *target_path,
                     const char *user)
{
    ScanSession       session;
    FileRecord       *records = NULL;
    int               count = 0;
    int               previous_scan;
    ComparisonResult  result;
    char              detail[MAX_DETAIL_LEN];

    memset(&session, 0, sizeof(ScanSession));
    session.scan_mode = MODE_CHECK;
    strncpy(session.target_path, target_path, MAX_PATH_LEN - 1);
    strncpy(session.run_by_user, user, MAX_USER_LEN - 1);

    /* Create scan session */
    if (db_insert_scan(db, &session) != 0) {
        fprintf(stderr, "[ERROR] Failed to create scan session\n");
        return -1;
    }

    /* Scan current state */
    if (scan_directory(target_path, &records, &count, session.scan_id) != 0) {
        fprintf(stderr, "[ERROR] Directory scan failed\n");
        return -1;
    }

    if (db_insert_file_records_batch(db, records, count) != 0) {
        fprintf(stderr, "[ERROR] Failed to store file records\n");
        free(records);
        return -1;
    }

    free(records);

    /* Find the previous scan to compare against */
    previous_scan = db_get_latest_scan_id(db, target_path, session.scan_id);
    if (previous_scan < 0) {
        printf("[WARN] No previous baseline found for %s\n", target_path);
        printf("       Run with --baseline first.\n");
        return -1;
    }

    printf("[INFO] Comparing scan %d against baseline %d\n",
           session.scan_id, previous_scan);

    /* Run the comparison */
    if (compare_scans(db, session.scan_id, previous_scan, &result) != 0) {
        fprintf(stderr, "[ERROR] Comparison failed\n");
        return -1;
    }

    /* Display summary */
    print_summary(&result);

    /* Update totals */
    int total_changes = result.modified + result.new_files + result.deleted;
    db_update_scan_totals(db, session.scan_id, count, total_changes);

    /* Audit log */
    snprintf(detail, sizeof(detail),
             "Check scan of %s: %d files, %d changes (%d critical)",
             target_path, count, total_changes, result.critical_changes);
    db_write_audit_log(db, "CHECK", user, detail);

    return 0;
}

/*
 * run_report - Display the stored report for a target path.
 */
static int run_report(sqlite3 *db, const char *target_path,
                      const char *user)
{
    char detail[MAX_DETAIL_LEN];

    snprintf(detail, sizeof(detail),
             "Report requested for %s", target_path);
    db_write_audit_log(db, "REPORT", user, detail);

    return print_report(db, target_path);
}

int main(int argc, char *argv[])
{
    sqlite3 *db = NULL;
    char     user[MAX_USER_LEN];
    int      exit_code = 0;

    if (argc < 2) {
        print_usage();
        return 1;
    }

    /* Handle --help before opening the database */
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage();
        return 0;
    }

    /* All other commands require a directory argument */
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Missing directory argument\n");
        print_usage();
        return 1;
    }

    /* Get the current username for audit logging */
    get_current_user(user, sizeof(user));

    /* Open the database */
    if (db_open(FIM_DB_FILE, &db) != 0) {
        fprintf(stderr, "[ERROR] Cannot open database\n");
        return 1;
    }

    /* Dispatch to the appropriate handler */
    if (strcmp(argv[1], "--baseline") == 0) {
        exit_code = run_baseline(db, argv[2], user);

    } else if (strcmp(argv[1], "--check") == 0) {
        exit_code = run_check(db, argv[2], user);

    } else if (strcmp(argv[1], "--report") == 0) {
        exit_code = run_report(db, argv[2], user);

    } else {
        fprintf(stderr, "[ERROR] Unknown command: %s\n", argv[1]);
        print_usage();
        exit_code = 1;
    }

    db_close(db);
    return exit_code != 0 ? 1 : 0;
}
