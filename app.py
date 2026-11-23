
from flask import Flask, render_template, jsonify, request
import sqlite3
import csv
from collections import defaultdict
from pathlib import Path

from database.db import (
    get_all_incidents,
    get_incident_by_id,
    get_incident_audit_logs,
    update_investigation,
    update_incident_status
)


# --------------------------------
# FLASK APPLICATION CONFIGURATION
# --------------------------------

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static"
)

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "database" / "ueba.db"
CSV_PATH = BASE_DIR / "data" / "sample_logs.csv"


# --------------------------------
# DATABASE CONNECTION
# --------------------------------

def get_db_connection():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


# --------------------------------
# GET DASHBOARD DATA
# --------------------------------

def get_dashboard_data():

    connection = get_db_connection()

    try:

        users = connection.execute("""
            SELECT username, risk_score, risk_level,
                   reasons, timestamp
            FROM user_risk_assessments
            WHERE id IN (
                SELECT MAX(id)
                FROM user_risk_assessments
                GROUP BY username
            )
            ORDER BY risk_score DESC
        """).fetchall()

    finally:
        connection.close()

    total_users = len(users)

    low_risk = sum(
        1 for user in users
        if user["risk_level"] == "LOW"
    )

    medium_risk = sum(
        1 for user in users
        if user["risk_level"] == "MEDIUM"
    )

    high_risk = sum(
        1 for user in users
        if user["risk_level"] == "HIGH"
    )

    critical_risk = sum(
        1 for user in users
        if user["risk_level"] == "CRITICAL"
    )

    risk_distribution = {
        "labels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "values": [
            low_risk,
            medium_risk,
            high_risk,
            critical_risk
        ]
    }

    return {
        "users": users,
        "total_users": total_users,
        "low_risk": low_risk,
        "medium_risk": medium_risk,
        "high_risk": high_risk,
        "critical_risk": critical_risk,
        "risk_distribution": risk_distribution
    }


# --------------------------------
# LOGIN ACTIVITY API
# --------------------------------

@app.route("/api/login-activity")
def login_activity():

    activity = defaultdict(
        lambda: {"success": 0, "failed": 0}
    )

    if not CSV_PATH.exists():

        return jsonify({
            "error": "Sample login log file not found"
        }), 404

    with open(
        CSV_PATH,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(file)

        for event in reader:

            timestamp = event.get("timestamp", "")
            status = event.get("status", "").strip().lower()

            if not timestamp:
                continue

            date = timestamp[:10]

            if status == "success":
                activity[date]["success"] += 1

            elif status == "failed":
                activity[date]["failed"] += 1

    dates = sorted(activity.keys())

    return jsonify({
        "labels": dates,
        "successful": [
            activity[date]["success"]
            for date in dates
        ],
        "failed": [
            activity[date]["failed"]
            for date in dates
        ]
    })


# --------------------------------
# INCIDENT HISTORY API
# --------------------------------

@app.route("/api/incidents")
def get_incidents():

    try:

        incidents = get_all_incidents()

        return jsonify({
            "total_incidents": len(incidents),
            "incidents": incidents
        })

    except sqlite3.Error:

        app.logger.exception(
            "Unable to retrieve incidents"
        )

        return jsonify({
            "error": "Unable to retrieve incident records"
        }), 500


# --------------------------------
# GET SINGLE INCIDENT DETAILS
# --------------------------------

@app.route("/api/incidents/<int:incident_id>")
def incident_details(incident_id):

    try:

        incident = get_incident_by_id(incident_id)

        if incident is None:

            return jsonify({
                "error": "Incident not found"
            }), 404

        return jsonify({
            "incident": incident
        })

    except sqlite3.Error:

        app.logger.exception(
            "Unable to retrieve incident details"
        )

        return jsonify({
            "error": "Unable to retrieve incident details"
        }), 500


# --------------------------------
# INCIDENT AUDIT HISTORY API
# --------------------------------

@app.route("/api/incidents/<int:incident_id>/audit")
def incident_audit_history(incident_id):

    try:

        incident = get_incident_by_id(incident_id)

        if incident is None:

            return jsonify({
                "error": "Incident not found"
            }), 404

        audit_logs = get_incident_audit_logs(
            incident_id
        )

        return jsonify({
            "incident_id": incident_id,
            "total_audit_records": len(audit_logs),
            "audit_history": audit_logs
        })

    except sqlite3.Error:

        app.logger.exception(
            "Unable to retrieve incident audit history"
        )

        return jsonify({
            "error": "Unable to retrieve audit history"
        }), 500


# --------------------------------
# IP ADDRESS INVESTIGATION API
# --------------------------------

@app.route(
    "/api/incidents/<int:incident_id>/ip-investigation"
)
def ip_investigation(incident_id):

    try:

        # Retrieve the selected incident
        incident = get_incident_by_id(incident_id)

        if incident is None:

            return jsonify({
                "error": "Incident not found"
            }), 404

        if not CSV_PATH.exists():

            return jsonify({
                "error": "Sample login log file not found"
            }), 404

        target_ip = str(
            incident.get("ip_address") or ""
        ).strip()

        target_username = str(
            incident.get("username") or ""
        ).strip()

        related_events = []

        successful_count = 0
        failed_count = 0

        # Read login records from sample CSV
        with open(
            CSV_PATH,
            "r",
            newline="",
            encoding="utf-8-sig"
        ) as file:

            reader = csv.DictReader(file)

            for event in reader:

                event_ip = str(
                    event.get("ip_address", "")
                ).strip()

                event_username = str(
                    event.get("username", "")
                ).strip()

                status = str(
                    event.get("status", "")
                ).strip().lower()

                # Match incident IP and username
                if (
                    event_ip == target_ip
                    and event_username == target_username
                ):

                    if status == "success":
                        successful_count += 1

                    elif status == "failed":
                        failed_count += 1

                    related_events.append({
                        "username": event_username,
                        "timestamp": event.get(
                            "timestamp", ""
                        ),
                        "ip_address": event_ip,
                        "status": status
                    })

        # Sort events by timestamp
        related_events.sort(
            key=lambda event: event["timestamp"]
        )

        return jsonify({

            "incident": {
                "id": incident["id"],
                "username": target_username,
                "ip_address": target_ip,
                "alert_type": incident["alert_type"],
                "severity": incident["severity"],
                "status": incident["status"],
                "detected_at": incident["detected_at"]
            },

            "login_summary": {
                "successful_logins": successful_count,
                "failed_logins": failed_count,
                "total_logins": len(related_events)
            },

            "related_activity": related_events,

            "evidence": (
                incident.get("evidence")
                or incident.get("details")
                or "No evidence available"
            ),

            "recommended_action": (
                incident.get("recommended_action")
                or "Review the related login activity"
            ),

            "data_source": "Simulated sample login dataset"
        })

    except (
        sqlite3.Error,
        OSError,
        csv.Error,
        ValueError
    ):

        app.logger.exception(
            "Unable to investigate incident IP address"
        )

        return jsonify({
            "error": "Unable to retrieve IP investigation data"
        }), 500


# --------------------------------
# SUSPICIOUS IP ALERTS API
# --------------------------------

@app.route("/api/ip-alerts")
def ip_alerts():

    try:

        incidents = get_all_incidents()

        return jsonify({
            "total_alerts": len(incidents),
            "alerts": incidents
        })

    except sqlite3.Error:

        app.logger.exception(
            "Unable to retrieve IP alerts"
        )

        return jsonify({
            "error": "Unable to retrieve IP alerts"
        }), 500


# --------------------------------
# UPDATE INCIDENT STATUS API
# --------------------------------

@app.route(
    "/api/incidents/<int:incident_id>/status",
    methods=["POST"]
)
def change_incident_status(incident_id):

    data = request.get_json(silent=True) or {}

    new_status = str(
        data.get("status", "")
    ).strip().upper()

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:

        return jsonify({
            "error": "Invalid status",
            "allowed_statuses": allowed_statuses
        }), 400

    try:

        updated = update_incident_status(
            incident_id,
            new_status
        )

        if not updated:

            return jsonify({
                "error": "Incident not found"
            }), 404

        return jsonify({
            "message": "Incident status updated successfully",
            "incident_id": incident_id,
            "status": new_status
        })

    except (sqlite3.Error, ValueError):

        app.logger.exception(
            "Unable to update incident status"
        )

        return jsonify({
            "error": "Unable to update incident status"
        }), 500


# --------------------------------
# SAVE INVESTIGATION NOTES API
# --------------------------------

@app.route(
    "/api/incidents/<int:incident_id>/investigation",
    methods=["POST"]
)
def save_investigation(incident_id):

    data = request.get_json(silent=True) or {}

    analyst_notes = data.get("analyst_notes", "")

    if not isinstance(analyst_notes, str):

        return jsonify({
            "error": "Investigation notes must be text"
        }), 400

    analyst_notes = analyst_notes.strip()

    if len(analyst_notes) > 5000:

        return jsonify({
            "error": "Investigation notes cannot exceed 5000 characters"
        }), 400

    status = data.get("status")

    if status is not None:

        if not isinstance(status, str):

            return jsonify({
                "error": "Invalid incident status"
            }), 400

        status = status.strip().upper()

        if status not in [
            "OPEN",
            "INVESTIGATING",
            "RESOLVED"
        ]:

            return jsonify({
                "error": "Invalid incident status"
            }), 400

    try:

        updated = update_investigation(
            incident_id,
            analyst_notes,
            status
        )

        if not updated:

            return jsonify({
                "error": "Incident not found"
            }), 404

        return jsonify({
            "message": "Investigation saved successfully",
            "incident_id": incident_id,
            "analyst_notes": analyst_notes,
            "status": status
        })

    except (sqlite3.Error, ValueError):

        app.logger.exception(
            "Unable to save investigation"
        )

        return jsonify({
            "error": "Unable to save investigation"
        }), 500


# --------------------------------
# MAIN SOC DASHBOARD
# --------------------------------

@app.route("/")
def dashboard():

    data = get_dashboard_data()

    return render_template(
        "index.html",
        **data
    )


# --------------------------------
# APPLICATION START
# --------------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )
