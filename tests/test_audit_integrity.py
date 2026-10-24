import hashlib

from backend.database import SessionLocal
from backend.models import AuditLog


def test_audit_hash_chain_is_valid():
    db = SessionLocal()

    try:
        logs = (
            db.query(AuditLog)
            .order_by(AuditLog.id.asc())
            .all()
        )

        assert logs, "No audit logs found"

        previous_hash = "GENESIS"

        for log in logs:
            assert log.previous_hash == previous_hash, (
                f"Audit chain broken at ID {log.id}"
            )

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

            assert log.event_hash == expected_hash, (
                f"Audit hash mismatch at ID {log.id}"
            )

            previous_hash = log.event_hash

    finally:
        db.close()