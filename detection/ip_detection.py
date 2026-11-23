import pandas as pd
from pathlib import Path

from database.db import save_incident


# --------------------------------
# FILE CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "data" / "sample_logs.csv"
BASELINE_FILE = BASE_DIR / "data" / "baseline_ips.csv"

BRUTE_FORCE_WINDOW_MINUTES = 10
MIN_SUCCESSFUL_LOGINS_FOR_BASELINE = 3
UNUSUAL_TIME_THRESHOLD_HOURS = 4


# --------------------------------
# HELPER: CIRCULAR TIME DIFFERENCE
# --------------------------------

def hour_difference(hour1, hour2):

    difference = abs(hour1 - hour2)

    return min(difference, 24 - difference)


# --------------------------------
# HELPER: NORMAL LOGIN HOUR
# --------------------------------

def calculate_normal_login_hour(hours):

    if len(hours) == 0:
        return None

    # Select the observed hour with the smallest
    # total circular distance from the other hours.
    candidates = sorted(set(hours))

    normal_hour = min(
        candidates,
        key=lambda candidate: sum(
            hour_difference(candidate, hour)
            for hour in hours
        )
    )

    return normal_hour


# --------------------------------
# HELPER: FAILED LOGIN WINDOW
# --------------------------------

def get_max_failed_attempts(events):

    events = events.dropna(
        subset=["parsed_timestamp"]
    ).sort_values("parsed_timestamp")

    timestamps = events["parsed_timestamp"].tolist()

    max_attempts = 0
    window_start = 0

    for window_end in range(len(timestamps)):

        while (
            timestamps[window_end] - timestamps[window_start]
        ).total_seconds() > BRUTE_FORCE_WINDOW_MINUTES * 60:

            window_start += 1

        attempts = window_end - window_start + 1

        max_attempts = max(max_attempts, attempts)

    return max_attempts


# --------------------------------
# MAIN IP AND BEHAVIOR DETECTION
# --------------------------------

def detect_ip_anomalies():

    if not LOG_FILE.exists():
        raise FileNotFoundError(
            f"Log file not found: {LOG_FILE}"
        )

    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            f"Baseline file not found: {BASELINE_FILE}"
        )

    baseline = pd.read_csv(BASELINE_FILE)
    logs = pd.read_csv(LOG_FILE)

    required_log_columns = {
        "username",
        "timestamp",
        "ip_address",
        "status"
    }

    required_baseline_columns = {
        "username",
        "ip_address"
    }

    if not required_log_columns.issubset(logs.columns):
        raise ValueError(
            "Login log file is missing required columns."
        )

    if not required_baseline_columns.issubset(baseline.columns):
        raise ValueError(
            "Baseline IP file is missing required columns."
        )

    # Normalize values
    baseline["username"] = (
        baseline["username"].astype(str).str.strip()
    )

    baseline["ip_address"] = (
        baseline["ip_address"].astype(str).str.strip()
    )

    logs["username"] = (
        logs["username"].astype(str).str.strip()
    )

    logs["ip_address"] = (
        logs["ip_address"].astype(str).str.strip()
    )

    logs["status"] = (
        logs["status"].astype(str).str.strip().str.lower()
    )

    logs["parsed_timestamp"] = pd.to_datetime(
        logs["timestamp"],
        errors="coerce"
    )

    known_ips = (
        baseline.groupby("username")["ip_address"]
        .apply(set)
        .to_dict()
    )

    alerts = []

    print("\n===== UEBA BEHAVIOR DETECTION =====\n")

    # --------------------------------
    # 1. UNFAMILIAR SUCCESSFUL IP
    # --------------------------------

    successful = logs[
        logs["status"] == "success"
    ]

    for _, event in successful.iterrows():

        username = event["username"]
        ip = event["ip_address"]

        user_known_ips = known_ips.get(
            username,
            set()
        )

        if ip not in user_known_ips:

            alert = {
                "username": username,
                "ip_address": ip,
                "alert_type": "New IP Login",
                "severity": "HIGH",
                "details": (
                    "Successful login from an unfamiliar IP"
                )
            }

            alerts.append(alert)
            save_incident(alert)

            print(
                f"[HIGH] New IP detected | "
                f"User: {username} | IP: {ip}"
            )

    # --------------------------------
    # 2. UNUSUAL LOGIN TIME
    # --------------------------------

    print("\n--- Unusual Login Time Detection ---")

    for username, user_events in successful.groupby("username"):

        valid_events = user_events.dropna(
            subset=["parsed_timestamp"]
        ).copy()

        if len(valid_events) < MIN_SUCCESSFUL_LOGINS_FOR_BASELINE:
            continue

        valid_events["login_hour"] = (
            valid_events["parsed_timestamp"].dt.hour
            + valid_events["parsed_timestamp"].dt.minute / 60
        )

        normal_hour = calculate_normal_login_hour(
            valid_events["login_hour"].tolist()
        )

        for _, event in valid_events.iterrows():

            login_hour = event["login_hour"]

            difference = hour_difference(
                login_hour,
                normal_hour
            )

            if difference >= UNUSUAL_TIME_THRESHOLD_HOURS:

                login_time = event["parsed_timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                alert = {
                    "username": username,
                    "ip_address": event["ip_address"],
                    "alert_type": "Unusual Login Time",
                    "severity": "MEDIUM",
                    "details": (
                        f"Login at {login_time}; "
                        f"normal login hour is approximately "
                        f"{normal_hour:.2f}:00"
                    )
                }

                alerts.append(alert)
                save_incident(alert)

                print(
                    f"[MEDIUM] Unusual login time | "
                    f"User: {username} | "
                    f"Time: {login_time}"
                )

    # --------------------------------
    # 3. BRUTE-FORCE DETECTION
    # --------------------------------

    print("\n--- Brute-Force Detection ---")

    failed = logs[
        logs["status"] == "failed"
    ]

    for (username, ip), events in failed.groupby(
        ["username", "ip_address"]
    ):

        max_attempts = get_max_failed_attempts(events)

        if max_attempts >= 2:

            alert = {
                "username": username,
                "ip_address": ip,
                "alert_type": "Multiple Failed Logins",
                "severity": "HIGH",
                "details": (
                    f"{max_attempts} failed login attempts "
                    f"detected within "
                    f"{BRUTE_FORCE_WINDOW_MINUTES} minutes"
                )
            }

            alerts.append(alert)
            save_incident(alert)

            print(
                f"[HIGH] Possible brute-force behavior | "
                f"User: {username} | IP: {ip} | "
                f"Attempts: {max_attempts}"
            )

    # --------------------------------
    # FINAL RESULTS
    # --------------------------------

    if not alerts:
        print("No suspicious activity detected.")

    print(f"\nTotal alerts detected: {len(alerts)}")

    return alerts


# --------------------------------
# MAIN EXECUTION
# --------------------------------

if __name__ == "__main__":
    detect_ip_anomalies()