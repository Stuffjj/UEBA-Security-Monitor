
from database.db import (
    initialize_database,
    update_incident_status,
    get_incident_audit_logs
)

initialize_database()

incident_id = 2

print("\n--- Updating Incident Status ---")

success = update_incident_status(
    incident_id,
    "INVESTIGATING"
)

if success:
    print("[SUCCESS] Incident status updated")

print("\n--- Audit History ---")

logs = get_incident_audit_logs(incident_id)

for log in logs:
    print(log)
