/*
 * fim_types.h
 * File Integrity Monitor - Shared Type Definitions
 *
 * Defines the structs and enums shared across all modules.
 * Keeping types in one header prevents circular dependencies
 * and ensures consistent data representation.
 *
 * Author: Joseph Black
 */

#ifndef FIM_TYPES_H
#define FIM_TYPES_H

#include <time.h>

/* Maximum path and hash lengths - enforced at every boundary */
#define MAX_PATH_LEN   1024
#define MAX_HASH_LEN   65    /* SHA-256 hex string (64 chars + null) */
#define MAX_USER_LEN   64
#define MAX_PERMS_LEN  16    /* e.g. "-rwxr-xr-x" */
#define MAX_DETAIL_LEN 256

/*
 * ChangeStatus - what happened to a file between two scans.
 * BASELINE means this is the first time we've seen the file.
 */
typedef enum {
    STATUS_BASELINE  = 0,
    STATUS_NEW       = 1,
    STATUS_UNCHANGED = 2,
    STATUS_MODIFIED  = 3,
    STATUS_DELETED   = 4
} ChangeStatus;

/*
 * ChangeClass - how critical is this change?
 * EXPECTED:   matches a known vendor update manifest
 * UNEXPECTED: file changed but wasn't in the manifest
 * CRITICAL:   a protected/sensitive file was altered
 * NONE:       no change occurred (UNCHANGED or BASELINE)
 */
typedef enum {
    CLASS_NONE       = 0,
    CLASS_EXPECTED   = 1,
    CLASS_UNEXPECTED = 2,
    CLASS_CRITICAL   = 3
} ChangeClass;

/*
 * ScanMode - what operation the user requested.
 * BASELINE: first scan, populate the database
 * CHECK:    compare current state against last baseline
 * REPORT:   display stored comparison results
 */
typedef enum {
    MODE_BASELINE = 0,
    MODE_CHECK    = 1,
    MODE_REPORT   = 2
} ScanMode;

/*
 * FileRecord - one file observed during one scan.
 * This struct is populated by the scanner and passed
 * to the database layer for storage.
 */
typedef struct {
    int           record_id;
    int           scan_id;
    char          file_path[MAX_PATH_LEN];
    char          file_name[MAX_PATH_LEN];
    char          sha256_hash[MAX_HASH_LEN];
    long          file_size;
    char          file_permissions[MAX_PERMS_LEN];
    char          last_modified[MAX_DETAIL_LEN];
    ChangeStatus  change_status;
    ChangeClass   change_class;
} FileRecord;

/*
 * ScanSession - metadata for one execution of the tool.
 * Created at the start of every scan and updated with
 * totals when the scan completes.
 */
typedef struct {
    int       scan_id;
    ScanMode  scan_mode;
    char      target_path[MAX_PATH_LEN];
    char      run_by_user[MAX_USER_LEN];
    char      timestamp[MAX_DETAIL_LEN];
    int       files_scanned;
    int       changes_found;
} ScanSession;

/*
 * Helper: convert enum to readable string for display and storage.
 */
static inline const char *status_to_string(ChangeStatus s) {
    switch (s) {
        case STATUS_BASELINE:  return "BASELINE";
        case STATUS_NEW:       return "NEW";
        case STATUS_UNCHANGED: return "UNCHANGED";
        case STATUS_MODIFIED:  return "MODIFIED";
        case STATUS_DELETED:   return "DELETED";
        default:               return "UNKNOWN";
    }
}

static inline const char *class_to_string(ChangeClass c) {
    switch (c) {
        case CLASS_NONE:       return "NONE";
        case CLASS_EXPECTED:   return "EXPECTED";
        case CLASS_UNEXPECTED: return "UNEXPECTED";
        case CLASS_CRITICAL:   return "CRITICAL";
        default:               return "UNKNOWN";
    }
}

static inline const char *mode_to_string(ScanMode m) {
    switch (m) {
        case MODE_BASELINE: return "BASELINE";
        case MODE_CHECK:    return "CHECK";
        case MODE_REPORT:   return "REPORT";
        default:            return "UNKNOWN";
    }
}

#endif /* FIM_TYPES_H */
