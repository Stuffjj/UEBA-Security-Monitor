
import tempfile
from pathlib import Path

import pandas as pd
import detection.ip_detection as detector


def run_integration_test():

    # Preserve the original configuration
    original_log_file = detector.LOG_FILE
    original_baseline_file = detector.BASELINE_FILE
    original_save_incident = detector.save_incident

    captured_alerts = []

    try:
        with tempfile.TemporaryDirectory() as temp_dir:

            temp_path = Path(temp_dir)

            test_logs = temp_path / "test_logs.csv"
            test_baseline = temp_path / "test_baseline.csv"

            # Isolated test login activity
            logs = pd.DataFrame([
                # Three normal successful logins
                ["alice", "2026-11-20 09:00:00", "10.0.0.10", "success"],
                ["alice", "2026-11-21 09:00:00", "10.0.0.10", "success"],
                ["alice", "2026-11-22 09:00:00", "10.0.0.10", "success"],

                # Successful login from unfamiliar IP at unusual time
                ["alice", "2026-11-23 03:00:00", "203.0.113.50", "success"],

                # Two failed login attempts within five minutes
                ["admin", "2026-11-23 10:00:00", "203.0.113.60", "failed"],
                ["admin", "2026-11-23 10:05:00", "203.0.113.60", "failed"],
            ], columns=[
                "username",
                "timestamp",
                "ip_address",
                "status"
            ])

            baseline = pd.DataFrame([
                ["alice", "10.0.0.10"],
                ["admin", "10.0.0.20"]
            ], columns=[
                "username",
                "ip_address"
            ])

            logs.to_csv(test_logs, index=False)
            baseline.to_csv(test_baseline, index=False)

            # Redirect detection to temporary test files
            detector.LOG_FILE = test_logs
            detector.BASELINE_FILE = test_baseline

            # Capture alerts instead of saving to SQLite
            detector.save_incident = captured_alerts.append

            print("\n===== FULL UEBA INTEGRATION TEST =====")

            alerts = detector.detect_ip_anomalies()

            alert_types = {
                alert["alert_type"]
                for alert in alerts
            }

            print("\n===== INTEGRATION TEST RESULTS =====")

            expected_alerts = {
                "New IP Login",
                "Unusual Login Time",
                "Multiple Failed Logins"
            }

            for alert_type in sorted(expected_alerts):

                if alert_type in alert_types:
                    print(f"[PASS] {alert_type}")
                else:
                    print(f"[FAIL] {alert_type}")

            assert expected_alerts.issubset(alert_types), (
                f"Missing alerts: {expected_alerts - alert_types}"
            )

            assert len(captured_alerts) == len(alerts)

            print("\nAll full detection workflow tests passed.")

    finally:
        # Restore the original project configuration
        detector.LOG_FILE = original_log_file
        detector.BASELINE_FILE = original_baseline_file
        detector.save_incident = original_save_incident


if __name__ == "__main__":
    run_integration_test()
