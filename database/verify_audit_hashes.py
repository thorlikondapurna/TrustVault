import hashlib

from backend.database import SessionLocal
from backend.models import AuditLog


db = SessionLocal()

try:
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.id.asc())
        .all()
    )

    previous_hash = "GENESIS"

    for log in logs:

        # Check that this record points to the previous record
        if log.previous_hash != previous_hash:
            print(f"❌ Chain broken at audit ID {log.id}")
            print("Expected previous hash:", previous_hash)
            print("Found:", log.previous_hash)
            break

        # Recreate the hash from the audit data
        event_data = (
            f"{log.user_id}|"
            f"{log.document_id}|"
            f"{log.action}|"
            f"{log.result}|"
            f"{log.details}|"
            f"{previous_hash}"
        )

        expected_hash = hashlib.sha256(
            event_data.encode("utf-8")
        ).hexdigest()

        # Check the event hash
        if log.event_hash != expected_hash:
            print(f"❌ Event hash mismatch at audit ID {log.id}")
            print("Expected:", expected_hash)
            print("Found:", log.event_hash)
            break

        previous_hash = log.event_hash

    else:
        print(f"✅ Audit hash chain is valid!")
        print(f"✅ Verified {len(logs)} audit records.")

finally:
    db.close()