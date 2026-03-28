/*
 * database.c
 * File Integrity Monitor - Database Module Implementation
 *
 * Manages all SQLite operations including table creation,
 * parameterized inserts, batch transactions, and audit logging.
 *
 * Security considerations:
 *   - EVERY query uses sqlite3_prepare_v2 with bound parameters
 *   - No string concatenation is used for query construction
 *   - Batch inserts use explicit BEGIN/COMMIT with ROLLBACK on error
 *   - WAL journal mode is enabled for crash safety
 *
 * Author: Joseph Black
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database.h"

/* SQL statements for table creation */
static const char *SQL_CREATE_SCANS =
    "CREATE TABLE IF NOT EXISTS scans ("
    "  scan_id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  scan_mode      TEXT    NOT NULL,"
    "  target_path    TEXT    NOT NULL,"
    "  run_by_user    TEXT    NOT NULL,"
    "  timestamp      TEXT    NOT NULL,"
    "  files_scanned  INTEGER DEFAULT 0,"
    "  changes_found  INTEGER DEFAULT 0"
    ");";

static const char *SQL_CREATE_FILE_RECORDS =
    "CREATE TABLE IF NOT EXISTS file_records ("
    "  record_id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  scan_id          INTEGER NOT NULL,"
    "  file_path        TEXT    NOT NULL,"
    "  file_name        TEXT    NOT NULL,"
    "  sha256_hash      TEXT    NOT NULL,"
    "  file_size        INTEGER NOT NULL,"
    "  file_permissions TEXT,"
    "  last_modified    TEXT,"
    "  change_status    TEXT    NOT NULL,"
    "  change_class     TEXT    NOT NULL,"
    "  FOREIGN KEY (scan_id) REFERENCES scans(scan_id)"
    ");";

static const char *SQL_CREATE_AUDIT_LOG =
    "CREATE TABLE IF NOT EXISTS audit_log ("
    "  log_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp  TEXT    NOT NULL,"
    "  action     TEXT    NOT NULL,"
    "  run_by_user TEXT   NOT NULL,"
    "  detail     TEXT"
    ");";

/* Index for faster lookups by scan_id and file_path */
static const char *SQL_CREATE_INDEX =
    "CREATE INDEX IF NOT EXISTS idx_records_scan_path "
    "ON file_records(scan_id, file_path);";

/*
 * Internal: get the current timestamp as an ISO-8601 string.
 */
static void get_timestamp(char *buffer, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info != NULL) {
        strftime(buffer, len, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "unknown", len - 1);
        buffer[len - 1] = '\0';
    }
}

/*
 * db_open - Open the database and create tables if needed.
 */
int db_open(const char *db_path, sqlite3 **db)
{
    char *err_msg = NULL;
    int   rc;

    if (db_path == NULL || db == NULL) {
        fprintf(stderr, "[ERROR] NULL parameter in db_open\n");
        return -1;
    }

    rc = sqlite3_open(db_path, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Cannot open database: %s\n",
                sqlite3_errmsg(*db));
        return -1;
    }

    /* Enable WAL mode for better crash safety */
    rc = sqlite3_exec(*db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[WARN] Could not set WAL mode: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    /* Enable foreign key enforcement */
    sqlite3_exec(*db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    /* Create tables */
    const char *create_stmts[] = {
        SQL_CREATE_SCANS,
        SQL_CREATE_FILE_RECORDS,
        SQL_CREATE_AUDIT_LOG,
        SQL_CREATE_INDEX,
        NULL
    };

    for (int i = 0; create_stmts[i] != NULL; i++) {
        rc = sqlite3_exec(*db, create_stmts[i], NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "[ERROR] Table creation failed: %s\n", err_msg);
            sqlite3_free(err_msg);
            sqlite3_close(*db);
            *db = NULL;
            return -1;
        }
    }

    return 0;
}

/*
 * db_close - Close the database connection safely.
 */
void db_close(sqlite3 *db)
{
    if (db != NULL) {
        sqlite3_close(db);
    }
}

/*
 * db_insert_scan - Insert a new scan session and return the scan_id.
 */
int db_insert_scan(sqlite3 *db, ScanSession *session)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql = "INSERT INTO scans (scan_mode, target_path, "
                        "run_by_user, timestamp) VALUES (?, ?, ?, ?);";
    char          ts[MAX_DETAIL_LEN];
    int           rc;

    if (db == NULL || session == NULL) {
        return -1;
    }

    get_timestamp(ts, sizeof(ts));
    strncpy(session->timestamp, ts, MAX_DETAIL_LEN - 1);
    session->timestamp[MAX_DETAIL_LEN - 1] = '\0';

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Prepare failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    /* Bind parameters - NEVER concatenate user input into SQL */
    sqlite3_bind_text(stmt, 1, mode_to_string(session->scan_mode), -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, session->target_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, session->run_by_user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ts, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[ERROR] Insert scan failed: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    session->scan_id = (int)sqlite3_last_insert_rowid(db);
    return 0;
}

/*
 * db_update_scan_totals - Update the summary counts after scanning.
 */
int db_update_scan_totals(sqlite3 *db, int scan_id,
                          int files_scanned, int changes_found)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql = "UPDATE scans SET files_scanned = ?, "
                        "changes_found = ? WHERE scan_id = ?;";
    int           rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, files_scanned);
    sqlite3_bind_int(stmt, 2, changes_found);
    sqlite3_bind_int(stmt, 3, scan_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/*
 * db_insert_file_record - Insert a single file observation.
 */
int db_insert_file_record(sqlite3 *db, const FileRecord *record)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql =
        "INSERT INTO file_records (scan_id, file_path, file_name, "
        "sha256_hash, file_size, file_permissions, last_modified, "
        "change_status, change_class) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] Prepare failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int (stmt, 1, record->scan_id);
    sqlite3_bind_text(stmt, 2, record->file_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record->file_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record->sha256_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, record->file_size);
    sqlite3_bind_text(stmt, 6, record->file_permissions, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, record->last_modified, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, status_to_string(record->change_status),
                      -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, class_to_string(record->change_class),
                      -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/*
 * db_insert_file_records_batch - Insert many records in one transaction.
 *
 * Wrapping in BEGIN/COMMIT dramatically improves performance
 * (from ~1 insert/sec to thousands/sec) and ensures atomicity.
 * On failure, the entire batch is rolled back.
 */
int db_insert_file_records_batch(sqlite3 *db, const FileRecord *records,
                                 int count)
{
    char *err_msg = NULL;
    int   rc;

    if (db == NULL || records == NULL || count <= 0) {
        return -1;
    }

    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] BEGIN failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (db_insert_file_record(db, &records[i]) != 0) {
            fprintf(stderr, "[ERROR] Insert failed at record %d, "
                    "rolling back\n", i);
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return -1;
        }
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[ERROR] COMMIT failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    return 0;
}

/*
 * db_get_latest_scan_id - Find the previous scan for comparison.
 *
 * Uses ORDER BY and LIMIT to find the most recent scan for the
 * same target path, excluding the current scan_id.
 */
int db_get_latest_scan_id(sqlite3 *db, const char *target_path,
                          int exclude_id)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql =
        "SELECT scan_id FROM scans "
        "WHERE target_path = ? AND scan_id != ? "
        "ORDER BY scan_id DESC LIMIT 1;";
    int rc, result = -1;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, target_path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, exclude_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return result;
}

/*
 * db_get_file_records - Retrieve all records for a scan session.
 *
 * Allocates and populates a FileRecord array. The caller
 * is responsible for freeing the returned array.
 */
int db_get_file_records(sqlite3 *db, int scan_id,
                        FileRecord **records, int *count)
{
    sqlite3_stmt *stmt = NULL;
    const char   *count_sql =
        "SELECT COUNT(*) FROM file_records WHERE scan_id = ?;";
    const char   *select_sql =
        "SELECT record_id, scan_id, file_path, file_name, "
        "sha256_hash, file_size, file_permissions, last_modified, "
        "change_status, change_class "
        "FROM file_records WHERE scan_id = ? ORDER BY file_path;";
    int rc, total = 0, idx = 0;

    /* First, get the count so we can allocate the right size */
    rc = sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, scan_id);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        total = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (total == 0) {
        *records = NULL;
        *count = 0;
        return 0;
    }

    /* Allocate the array */
    *records = calloc(total, sizeof(FileRecord));
    if (*records == NULL) {
        fprintf(stderr, "[ERROR] Failed to allocate records array\n");
        return -1;
    }

    /* Fetch the records */
    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(*records);
        *records = NULL;
        return -1;
    }
    sqlite3_bind_int(stmt, 1, scan_id);

    while (sqlite3_step(stmt) == SQLITE_ROW && idx < total) {
        FileRecord *r = &(*records)[idx];
        const char *text;

        r->record_id = sqlite3_column_int(stmt, 0);
        r->scan_id   = sqlite3_column_int(stmt, 1);

        text = (const char *)sqlite3_column_text(stmt, 2);
        if (text) strncpy(r->file_path, text, MAX_PATH_LEN - 1);

        text = (const char *)sqlite3_column_text(stmt, 3);
        if (text) strncpy(r->file_name, text, MAX_PATH_LEN - 1);

        text = (const char *)sqlite3_column_text(stmt, 4);
        if (text) strncpy(r->sha256_hash, text, MAX_HASH_LEN - 1);

        r->file_size = (long)sqlite3_column_int64(stmt, 5);

        text = (const char *)sqlite3_column_text(stmt, 6);
        if (text) strncpy(r->file_permissions, text, MAX_PERMS_LEN - 1);

        text = (const char *)sqlite3_column_text(stmt, 7);
        if (text) strncpy(r->last_modified, text, MAX_DETAIL_LEN - 1);

        /* Parse status and class strings back to enums */
        text = (const char *)sqlite3_column_text(stmt, 8);
        if (text) {
            if (strcmp(text, "NEW") == 0)       r->change_status = STATUS_NEW;
            else if (strcmp(text, "MODIFIED") == 0) r->change_status = STATUS_MODIFIED;
            else if (strcmp(text, "DELETED") == 0)  r->change_status = STATUS_DELETED;
            else if (strcmp(text, "UNCHANGED") == 0) r->change_status = STATUS_UNCHANGED;
            else r->change_status = STATUS_BASELINE;
        }

        text = (const char *)sqlite3_column_text(stmt, 9);
        if (text) {
            if (strcmp(text, "EXPECTED") == 0)    r->change_class = CLASS_EXPECTED;
            else if (strcmp(text, "UNEXPECTED") == 0) r->change_class = CLASS_UNEXPECTED;
            else if (strcmp(text, "CRITICAL") == 0)   r->change_class = CLASS_CRITICAL;
            else r->change_class = CLASS_NONE;
        }

        idx++;
    }

    sqlite3_finalize(stmt);
    *count = idx;
    return 0;
}

/*
 * db_write_audit_log - Record an action for accountability.
 *
 * Every tool operation (scan, check, report, export) is logged
 * with who did it and when. This supports NIST AU-12 audit
 * generation requirements.
 */
int db_write_audit_log(sqlite3 *db, const char *action,
                       const char *user, const char *detail)
{
    sqlite3_stmt *stmt = NULL;
    const char   *sql =
        "INSERT INTO audit_log (timestamp, action, run_by_user, detail) "
        "VALUES (?, ?, ?, ?);";
    char ts[MAX_DETAIL_LEN];
    int  rc;

    get_timestamp(ts, sizeof(ts));

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ts, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, action ? action : "UNKNOWN", -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user ? user : "unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, detail ? detail : "", -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
