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
        event_data = (
            f"{log.user_id}|"
            f"{log.document_id}|"
            f"{log.action}|"
            f"{log.result}|"
            f"{log.details}|"
            f"{previous_hash}"
        )

        event_hash = hashlib.sha256(
            event_data.encode("utf-8")
        ).hexdigest()

        log.previous_hash = previous_hash
        log.event_hash = event_hash

        previous_hash = event_hash

    db.commit()

    print(f"Successfully hashed {len(logs)} audit records.")

finally:
    db.close()