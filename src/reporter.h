/*
 * reporter.h
 * File Integrity Monitor - Reporter Module Interface
 *
 * Compares scan sessions, classifies changes, and generates
 * color-coded terminal output with summary statistics.
 *
 * Author: Joseph Black
 */

#ifndef REPORTER_H
#define REPORTER_H

#include <sqlite3.h>
#include "fim_types.h"

/*
 * ComparisonResult - summary statistics from comparing two scans.
 */
typedef struct {
    int total_current;
    int total_previous;
    int unchanged;
    int modified;
    int new_files;
    int deleted;
    int critical_changes;
    int unexpected_changes;
    int expected_changes;
} ComparisonResult;

/*
 * compare_scans - Compare current scan against a previous baseline.
 *
 * Updates the change_status and change_class fields on the current
 * scan's file_records in the database, then prints a diff report.
 *
 * Parameters:
 *   db             - database handle
 *   current_scan   - the scan just completed
 *   previous_scan  - the baseline scan to compare against
 *   result         - populated with summary statistics
 *
 * Returns: 0 on success, -1 on failure
 */
int compare_scans(sqlite3 *db, int current_scan, int previous_scan,
                  ComparisonResult *result);

/*
 * print_report - Display the last comparison result from the database.
 *
 * Retrieves and displays file records for a given scan session,
 * showing only entries that have a non-BASELINE status.
 */
int print_report(sqlite3 *db, const char *target_path);

/*
 * print_summary - Display a compact summary of comparison results.
 */
void print_summary(const ComparisonResult *result);

#endif /* REPORTER_H */
