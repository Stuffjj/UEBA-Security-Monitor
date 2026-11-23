
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime


# --------------------------------
# DATABASE CONFIGURATION
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "ueba.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def current_timestamp():
    return datetime.now().isoformat(timespec="seconds")


# --------------------------------
# RECOMMENDED RESPONSE ACTIONS
# --------------------------------

def get_recommended_action(alert_type):

    alert_type = alert_type.lower()

    if "new ip" in alert_type:
        return (
            "Verify whether the IP address belongs to the user. "
            "Review login history and investigate unfamiliar access. "
            "Escalate if the login is unauthorized."
        )

    elif "failed login" in alert_type:
        return (
            "Review failed login attempts, check the source IP, "
            "verify account activity and investigate possible "
            "brute-force behavior."
        )

    return (
        "Review the alert evidence, validate the activity, "
        "document findings and escalate if suspicious."
    )


# --------------------------------
# AUDIT LOG HELPER
# --------------------------------

def record_audit(
    incident_id,
    action,
    previous_status,
    new_status,
    analyst_notes=""
):
    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO incident_audit_logs (
                incident_id,
                action,
                previous_status,
                new_status,
                analyst_notes,
                changed_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id,
            action,
            previous_status,
            new_status,
            analyst_notes,
            current_timestamp()
        ))

        connection.commit()

    finally:
        connection.close()


# --------------------------------
# DATABASE INITIALIZATION
# --------------------------------

def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # User risk assessment table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            reasons TEXT
        )
    """)

    # Security incidents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            fingerprint TEXT NOT NULL UNIQUE,
            evidence TEXT,
            recommended_action TEXT,
            analyst_notes TEXT,
            updated_at TEXT
        )
    """)

    # Check existing incident columns
    cursor.execute("PRAGMA table_info(security_incidents)")

    existing_columns = {
        column["name"] for column in cursor.fetchall()
    }

    # Safely add missing columns
    new_columns = {
        "evidence": "TEXT",
        "recommended_action": "TEXT",
        "analyst_notes": "TEXT",
        "updated_at": "TEXT"
    }

    for column_name, column_type in new_columns.items():

        if column_name not in existing_columns:

            cursor.execute(
                f"ALTER TABLE security_incidents "
                f"ADD COLUMN {column_name} {column_type}"
            )

            print(f"[DATABASE] Added column: {column_name}")

    # Populate investigation details for existing incidents
    cursor.execute("""
        SELECT id, alert_type, details, detected_at,
               evidence, recommended_action,
               analyst_notes, updated_at
        FROM security_incidents
    """)

    incidents = cursor.fetchall()

    for incident in incidents:

        evidence = incident["evidence"] or incident["details"]

        recommended_action = (
            incident["recommended_action"]
            or get_recommended_action(incident["alert_type"])
        )

        analyst_notes = incident["analyst_notes"] or ""

        updated_at = (
            incident["updated_at"]
            or incident["detected_at"]
        )

        cursor.execute("""
            UPDATE security_incidents
            SET evidence = ?,
                recommended_action = ?,
                analyst_notes = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            evidence,
            recommended_action,
            analyst_notes,
            updated_at,
            incident["id"]
        ))

    # Incident audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            previous_status TEXT,
            new_status TEXT,
            analyst_notes TEXT,
            changed_at TEXT NOT NULL,
            FOREIGN KEY (incident_id)
                REFERENCES security_incidents(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_incident_id
        ON incident_audit_logs(incident_id)
    """)

    connection.commit()
    connection.close()

    print("[SUCCESS] UEBA database initialized")
    print("[SUCCESS] Security incidents table verified")
    print("[SUCCESS] Investigation fields verified")
    print("[SUCCESS] Incident audit log initialized")


# --------------------------------
# SAVE USER RISK ASSESSMENT
# --------------------------------

def save_assessment(username, score, level, reasons):

    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO user_risk_assessments (
                timestamp,
                username,
                risk_score,
                risk_level,
                reasons
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            current_timestamp(),
            username,
            score,
            level,
            reasons
        ))

        connection.commit()

    finally:
        connection.close()

    print(f"[DATABASE] Assessment saved for {username}")


# --------------------------------
# SAVE SECURITY INCIDENT
# --------------------------------

def save_incident(alert):

    username = alert["username"]
    ip_address = alert["ip_address"]
    alert_type = alert["alert_type"]
    severity = alert["severity"]
    details = alert["details"]

    evidence = alert.get("evidence") or details

    recommended_action = (
        alert.get("recommended_action")
        or get_recommended_action(alert_type)
    )

    fingerprint_data = (
        f"{username}|{ip_address}|{alert_type}|{details}"
    )

    fingerprint = hashlib.sha256(
        fingerprint_data.encode("utf-8")
    ).hexdigest()

    now = current_timestamp()

    connection = get_connection()

    try:
        cursor = connection.execute("""
            INSERT OR IGNORE INTO security_incidents (
                detected_at,
                username,
                ip_address,
                alert_type,
                severity,
                details,
                status,
                fingerprint,
                evidence,
                recommended_action,
                analyst_notes,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, '', ?)
        """, (
            now,
            username,
            ip_address,
            alert_type,
            severity,
            details,
            fingerprint,
            evidence,
            recommended_action,
            now
        ))

        inserted = cursor.rowcount == 1

        if inserted:
            incident_id = cursor.lastrowid
            print(f"[DATABASE] Incident #{incident_id} saved")
        else:
            incident_id = None
            print(
                f"[DATABASE] Duplicate incident skipped for {username}"
            )

        connection.commit()
        return incident_id

    finally:
        connection.close()


# --------------------------------
# GET ALL SECURITY INCIDENTS
# --------------------------------

def get_all_incidents():

    connection = get_connection()

    try:
        incidents = connection.execute("""
            SELECT *
            FROM security_incidents
            ORDER BY id DESC
        """).fetchall()

        return [dict(incident) for incident in incidents]

    finally:
        connection.close()


# --------------------------------
# GET INCIDENT BY ID
# --------------------------------

def get_incident_by_id(incident_id):

    connection = get_connection()

    try:
        incident = connection.execute("""
            SELECT *
            FROM security_incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        return dict(incident) if incident else None

    finally:
        connection.close()


# --------------------------------
# GET INCIDENT AUDIT HISTORY
# --------------------------------

def get_incident_audit_logs(incident_id):

    connection = get_connection()

    try:
        logs = connection.execute("""
            SELECT *
            FROM incident_audit_logs
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        return [dict(log) for log in logs]

    finally:
        connection.close()


# --------------------------------
# UPDATE INVESTIGATION DETAILS
# --------------------------------

def update_investigation(
    incident_id,
    analyst_notes,
    status=None
):

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    connection = get_connection()

    try:
        incident = connection.execute("""
            SELECT id, status, analyst_notes
            FROM security_incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            return False

        old_status = incident["status"]
        old_notes = incident["analyst_notes"] or ""

        new_status = status or old_status

        if new_status not in allowed_statuses:
            raise ValueError("Invalid incident status")

        if not isinstance(analyst_notes, str):
            raise ValueError("Analyst notes must be text")

        now = current_timestamp()

        connection.execute("""
            UPDATE security_incidents
            SET analyst_notes = ?,
                status = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            analyst_notes,
            new_status,
            now,
            incident_id
        ))

        if old_status != new_status or old_notes != analyst_notes:

            action = "INVESTIGATION_UPDATED"

            connection.execute("""
                INSERT INTO incident_audit_logs (
                    incident_id,
                    action,
                    previous_status,
                    new_status,
                    analyst_notes,
                    changed_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                action,
                old_status,
                new_status,
                analyst_notes,
                now
            ))

        connection.commit()

        print(
            f"[DATABASE] Investigation updated for incident #{incident_id}"
        )

        return True

    finally:
        connection.close()


# --------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------

def update_incident_status(incident_id, new_status):

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:
        raise ValueError("Invalid incident status")

    connection = get_connection()

    try:
        incident = connection.execute("""
            SELECT status
            FROM security_incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            return False

        old_status = incident["status"]

        if old_status == new_status:
            return True

        now = current_timestamp()

        connection.execute("""
            UPDATE security_incidents
            SET status = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            new_status,
            now,
            incident_id
        ))

        connection.execute("""
            INSERT INTO incident_audit_logs (
                incident_id,
                action,
                previous_status,
                new_status,
                analyst_notes,
                changed_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id,
            "STATUS_CHANGED",
            old_status,
            new_status,
            "",
            now
        ))

        connection.commit()

        print(
            f"[DATABASE] Status changed for incident #{incident_id}: "
            f"{old_status} -> {new_status}"
        )

        return True

    finally:
        connection.close()


# --------------------------------
# VIEW USER RISK ASSESSMENTS
# --------------------------------

def view_assessments():

    connection = get_connection()

    try:
        records = connection.execute("""
            SELECT id, timestamp, username,
                   risk_score, risk_level, reasons
            FROM user_risk_assessments
            ORDER BY id DESC
        """).fetchall()

    finally:
        connection.close()

    print("\n===== UEBA DATABASE RECORDS =====\n")

    for record in records:
        print(tuple(record))


# --------------------------------
# VIEW SECURITY INCIDENTS
# --------------------------------

def view_incidents():

    incidents = get_all_incidents()

    print("\n===== SECURITY INCIDENT RECORDS =====\n")

    for incident in incidents:

        print(
            f"ID: {incident['id']} | "
            f"User: {incident['username']} | "
            f"IP: {incident['ip_address']} | "
            f"Severity: {incident['severity']} | "
            f"Status: {incident['status']}"
        )

        print(f"Evidence: {incident['evidence']}")

        print(
            f"Recommended Action: "
            f"{incident['recommended_action']}"
        )

        print(f"Analyst Notes: {incident['analyst_notes']}")
        print(f"Last Updated: {incident['updated_at']}")
        print("-" * 60)


# --------------------------------
# MAIN
# --------------------------------

if __name__ == "__main__":

    initialize_database()
    view_assessments()
    view_incidents()
