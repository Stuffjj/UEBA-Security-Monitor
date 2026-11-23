
import tempfile
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from detection.risk_scoring import calculate_user_risk


def run_risk_tests():

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_path = Path(temp_dir)

        test_logs = temp_path / "risk_test_logs.csv"
        test_baseline = temp_path / "baseline_ips.csv"

        # Three test users with different risk scenarios
        logs = pd.DataFrame([
            # CRITICAL: All three suspicious behaviors
            ["critical_user", "2026-11-20 09:00:00", "10.0.0.40", "success"],
            ["critical_user", "2026-11-21 09:00:00", "10.0.0.40", "success"],
            ["critical_user", "2026-11-22 09:00:00", "10.0.0.40", "success"],
            ["critical_user", "2026-11-23 03:00:00", "203.0.113.80", "success"],
            ["critical_user", "2026-11-23 03:05:00", "203.0.113.80", "failed"],
            ["critical_user", "2026-11-23 03:08:00", "203.0.113.80", "failed"],
            # LOW: Normal login
            ["normal_user", "2026-11-20 09:00:00", "10.0.0.10", "success"],

            # MEDIUM: One failed login
            ["medium_user", "2026-11-20 09:00:00", "10.0.0.20", "success"],
            ["medium_user", "2026-11-20 09:05:00", "10.0.0.20", "failed"],

            # HIGH: Multiple failed logins + unfamiliar IP
            ["high_user", "2026-11-20 09:00:00", "10.0.0.30", "success"],
            ["high_user", "2026-11-20 09:05:00", "10.0.0.30", "failed"],
            ["high_user", "2026-11-20 09:07:00", "10.0.0.30", "failed"],
            ["high_user", "2026-11-20 09:10:00", "203.0.113.70", "success"],
        ], columns=[
            "username",
            "timestamp",
            "ip_address",
            "status"
        ])

        baseline = pd.DataFrame([
    ["normal_user", "10.0.0.10"],
    ["medium_user", "10.0.0.20"],
    ["high_user", "10.0.0.30"],
    ["critical_user", "10.0.0.40"]
], columns=["username", "ip_address"])
        
        logs.to_csv(test_logs, index=False)
        baseline.to_csv(test_baseline, index=False)

        # Replace the production baseline with the test baseline.
        # Mock database functions so no real database is changed.
        with patch(
            "detection.risk_scoring.BASELINE_FILE",
            test_baseline
        ), patch(
            "detection.risk_scoring.initialize_database"
        ), patch(
            "detection.risk_scoring.save_assessment"
        ):

            results = calculate_user_risk(test_logs)

        print("\n===== RISK SCORING TEST RESULTS =====")

        expected = {
    "normal_user": 0,
    "medium_user": 15,
    "high_user": 60,
    "critical_user": 90
}

        for username, expected_score in expected.items():

            actual_score = results[username]

            assert actual_score == expected_score, (
                f"{username}: expected {expected_score}, "
                f"received {actual_score}"
            )

            print(
                f"[PASS] {username}: "
                f"{actual_score}/100"
            )

        print("\nAll risk scoring tests passed.")


if __name__ == "__main__":
    run_risk_tests()
