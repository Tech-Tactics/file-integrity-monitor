/*
 * database.h
 * File Integrity Monitor - Database Module Interface
 *
 * All database operations use parameterized queries to prevent
 * SQL injection. This practice aligns with NIST secure coding
 * guidelines and the prepared statement approach advocated by
 * OWASP for any application handling sensitive data.
 *
 * Author: Joseph Black
 */

#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "fim_types.h"

/*
 * db_open - Open (or create) the FIM database file.
 *
 * Creates all tables if they do not already exist.
 * Sets WAL journal mode for safer concurrent access.
 *
 * Parameters:
 *   db_path - path to the .db file
 *   db      - pointer to sqlite3 handle (set by function)
 *
 * Returns: 0 on success, -1 on failure
 */
int db_open(const char *db_path, sqlite3 **db);

/*
 * db_close - Safely close the database connection.
 */
void db_close(sqlite3 *db);

/*
 * db_insert_scan - Create a new scan session record.
 *
 * Returns the new scan_id via the session struct, or -1 on failure.
 */
int db_insert_scan(sqlite3 *db, ScanSession *session);

/*
 * db_update_scan_totals - Update file count and change count
 * after a scan completes.
 */
int db_update_scan_totals(sqlite3 *db, int scan_id,
                          int files_scanned, int changes_found);

/*
 * db_insert_file_record - Insert one file observation.
 *
 * Uses parameterized binding for all values.
 */
int db_insert_file_record(sqlite3 *db, const FileRecord *record);

/*
 * db_insert_file_records_batch - Insert multiple records in a transaction.
 *
 * Wraps all inserts in BEGIN/COMMIT for performance.
 * On failure, rolls back the entire batch.
 */
int db_insert_file_records_batch(sqlite3 *db, const FileRecord *records,
                                 int count);

/*
 * db_get_latest_scan_id - Find the most recent scan for a given path.
 *
 * Parameters:
 *   db          - database handle
 *   target_path - the directory that was scanned
 *   exclude_id  - scan_id to exclude (usually the current scan)
 *
 * Returns: scan_id on success, -1 if no previous scan exists
 */
int db_get_latest_scan_id(sqlite3 *db, const char *target_path,
                          int exclude_id);

/*
 * db_get_file_records - Retrieve all file records for a given scan.
 *
 * Allocates and populates an array of FileRecord structs.
 * Caller must free the returned array.
 *
 * Returns: 0 on success, -1 on failure
 */
int db_get_file_records(sqlite3 *db, int scan_id,
                        FileRecord **records, int *count);

/*
 * db_write_audit_log - Record an action in the audit trail.
 *
 * Parameters:
 *   db      - database handle
 *   action  - short label: "BASELINE", "CHECK", "REPORT", "EXPORT"
 *   user    - username of who ran the action
 *   detail  - human-readable description of what happened
 */
int db_write_audit_log(sqlite3 *db, const char *action,
                       const char *user, const char *detail);

#endif /* DATABASE_H */
