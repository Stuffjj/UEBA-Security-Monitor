import pandas as pd
from pathlib import Path

from database.db import initialize_database, save_assessment


# --------------------------------
# CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

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

    candidates = sorted(set(hours))

    return min(
        candidates,
        key=lambda candidate: sum(
            hour_difference(candidate, hour)
            for hour in hours
        )
    )


# --------------------------------
# HELPER: MAX FAILED ATTEMPTS
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
# USER RISK SCORING
# --------------------------------

def calculate_user_risk(file_path):

    initialize_database()

    log_path = Path(file_path)

    if not log_path.is_absolute():
        log_path = BASE_DIR / log_path

    if not log_path.exists():
        raise FileNotFoundError(
            f"Login log file not found: {log_path}"
        )

    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            f"Baseline file not found: {BASELINE_FILE}"
        )

    df = pd.read_csv(log_path)
    baseline = pd.read_csv(BASELINE_FILE)

    required_columns = {
        "username",
        "timestamp",
        "ip_address",
        "status"
    }

    if not required_columns.issubset(df.columns):
        raise ValueError(
            "Login log file is missing required columns."
        )

    # Normalize login data
    df["username"] = (
        df["username"].astype(str).str.strip()
    )

    df["ip_address"] = (
        df["ip_address"].astype(str).str.strip()
    )

    df["status"] = (
        df["status"].astype(str).str.strip().str.lower()
    )

    df["parsed_timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    # Normalize baseline data
    baseline["username"] = (
        baseline["username"].astype(str).str.strip()
    )

    baseline["ip_address"] = (
        baseline["ip_address"].astype(str).str.strip()
    )

    known_ips = (
        baseline.groupby("username")["ip_address"]
        .apply(set)
        .to_dict()
    )

    print("\n===== UEBA USER RISK SCORING =====\n")

    risk_scores = {}

    # --------------------------------
    # ANALYZE EACH USER
    # --------------------------------

    for username in df["username"].unique():

        user_data = df[
            df["username"] == username
        ].copy()

        score = 0
        reasons = []

        # --------------------------------
        # 1. FAILED LOGIN DETECTION
        # --------------------------------

        failed = user_data[
            user_data["status"] == "failed"
        ]

        max_failed_attempts = 0

        for ip, events in failed.groupby("ip_address"):

            attempts = get_max_failed_attempts(events)

            max_failed_attempts = max(
                max_failed_attempts,
                attempts
            )

        if max_failed_attempts >= 2:

            score += 30

            reasons.append(
                "Multiple failed logins within 10 minutes"
            )

        elif max_failed_attempts == 1:

            score += 15

            reasons.append(
                "Failed login detected"
            )

        # --------------------------------
        # 2. UNUSUAL LOGIN TIME DETECTION
        # --------------------------------

        successful = user_data[
            user_data["status"] == "success"
        ].copy()

        if len(successful) >= MIN_SUCCESSFUL_LOGINS_FOR_BASELINE:

            successful = successful.dropna(
                subset=["parsed_timestamp"]
            ).copy()

            if len(successful) >= MIN_SUCCESSFUL_LOGINS_FOR_BASELINE:

                successful["login_hour"] = (
                    successful["parsed_timestamp"].dt.hour
                    + successful["parsed_timestamp"].dt.minute / 60
                )

                normal_hour = calculate_normal_login_hour(
                    successful["login_hour"].tolist()
                )

                unusual_time_found = False

                for hour in successful["login_hour"]:

                    difference = hour_difference(
                        hour,
                        normal_hour
                    )

                    if difference >= UNUSUAL_TIME_THRESHOLD_HOURS:

                        unusual_time_found = True
                        break

                if unusual_time_found:

                    score += 30

                    reasons.append(
                        "Unusual login time"
                    )

        # --------------------------------
        # 3. UNFAMILIAR IP DETECTION
        # --------------------------------

        user_known_ips = known_ips.get(
            username,
            set()
        )

        successful_ips = set(
            successful["ip_address"].tolist()
        )

        unfamiliar_ips = (
            successful_ips - user_known_ips
        )

        if unfamiliar_ips:

            score += 30

            reasons.append(
                "Successful login from unfamiliar IP"
            )

        # --------------------------------
        # 4. FINAL RISK SCORE
        # --------------------------------

        score = min(score, 100)

        if score >= 70:
            level = "CRITICAL"

        elif score >= 40:
            level = "HIGH"

        elif score >= 20:
            level = "MEDIUM"

        else:
            level = "LOW"

        reason_text = (
            ", ".join(reasons)
            if reasons
            else "No suspicious activity detected"
        )

        risk_scores[username] = score

        # --------------------------------
        # 5. DISPLAY RESULTS
        # --------------------------------

        print(f"User: {username}")
        print(f"Risk Score: {score}/100")
        print(f"Risk Level: {level}")
        print(f"Reasons: {reason_text}")

        # --------------------------------
        # 6. SAVE RESULTS TO SQLITE
        # --------------------------------

        save_assessment(
            username,
            score,
            level,
            reason_text
        )

        print("-" * 40)

    print("\nUEBA Risk Analysis Completed!")

    return risk_scores


# --------------------------------
# MAIN EXECUTION
# --------------------------------

if __name__ == "__main__":

    calculate_user_risk(
        "data/sample_logs.csv"
    )