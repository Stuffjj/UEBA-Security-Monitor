
import pandas as pd


def analyze_login_behavior(file_path):
    # Read login activity
    df = pd.read_csv(file_path)

    # Convert timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Extract login hour
    df["login_hour"] = df["timestamp"].dt.hour

    # Use successful logins to establish normal behavior
    successful = df[df["status"] == "success"]

    baseline = successful.groupby("username")["login_hour"].agg(
        ["mean", "std"]
    )

    # Check each login event
    print("\n===== UEBA LOGIN BEHAVIOR ANALYSIS =====\n")

    for _, event in df.iterrows():
        username = event["username"]
        hour = event["login_hour"]

        if username not in baseline.index:
            continue

        normal_hour = baseline.loc[username, "mean"]

        difference = abs(hour - normal_hour)
        difference = min(difference, 24 - difference)

        if event["status"] == "failed":
            print(
                f"[MEDIUM] Failed login detected | "
                f"User: {username} | IP: {event['ip_address']}"
            )

        elif difference >= 4:
            print(
                f"[HIGH] Unusual login time detected | "
                f"User: {username} | "
                f"Login hour: {hour}:00 | "
                f"Normal hour: {normal_hour:.1f}"
            )

        else:
            print(
                f"[NORMAL] User: {username} | "
                f"Login hour: {hour}:00"
            )


if __name__ == "__main__":
    analyze_login_behavior("data/sample_logs.csv")
