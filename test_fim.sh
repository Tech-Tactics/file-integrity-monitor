#!/bin/bash
# test_fim.sh - Quick test to verify the FIM tool works
#
# Creates a test directory, runs baseline, modifies files,
# then runs a check to demonstrate the full workflow.

set -e

echo "=== FIM Test Script ==="
echo ""

# Clean up any previous test
rm -rf test_dir fim_data.db

# Step 1: Create test files
echo "[TEST] Creating test directory with sample files..."
mkdir -p test_dir
echo "This is a config file" > test_dir/app.conf
echo "Important data here" > test_dir/data.txt
echo "#!/bin/bash" > test_dir/startup.sh
echo "Log entry 1" > test_dir/access.log
echo "Public key placeholder" > test_dir/server.pem
chmod 644 test_dir/*
chmod 755 test_dir/startup.sh

echo "[TEST] Test directory created with 5 files"
echo ""

# Step 2: Run baseline
echo "[TEST] Running baseline scan..."
echo "---"
./fim --baseline ./test_dir
echo "---"
echo ""

# Step 3: Simulate changes (like a vendor update or intrusion)
echo "[TEST] Simulating file changes..."
echo "Modified config content" > test_dir/app.conf       # MODIFIED
echo "Unauthorized script" > test_dir/backdoor.sh         # NEW file
rm test_dir/access.log                                     # DELETED
# data.txt and startup.sh remain unchanged
# server.pem remains unchanged (but is a critical path)
echo "[TEST] Changes applied: 1 modified, 1 new, 1 deleted"
echo ""

# Step 4: Run integrity check
echo "[TEST] Running integrity check..."
echo "---"
./fim --check ./test_dir
echo "---"
echo ""

# Step 5: View report
echo "[TEST] Running stored report..."
echo "---"
./fim --report ./test_dir
echo "---"
echo ""

# Step 6: Show the audit log
echo "[TEST] Audit log contents:"
echo "---"
sqlite3 fim_data.db "SELECT timestamp, action, run_by_user, detail FROM audit_log ORDER BY log_id;"
echo "---"
echo ""

echo "=== Test Complete ==="
