import hashlib

from backend.models import AuditLog


def create_audit_log(
    db,
    user_id,
    action,
    result,
    document_id=None,
    details=None
):
    # Get the most recent audit event
    previous_log = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )

    previous_hash = previous_log.event_hash if previous_log else "GENESIS"

    # Create a consistent string representing this event
    event_data = (
        f"{user_id}|"
        f"{document_id}|"
        f"{action}|"
        f"{result}|"
        f"{details}|"
        f"{previous_hash}"
    )

    # Generate SHA-256 hash
    event_hash = hashlib.sha256(
        event_data.encode("utf-8")
    ).hexdigest()

    log = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        result=result,
        details=details,
        previous_hash=previous_hash,
        event_hash=event_hash
    )

    db.add(log)
    db.commit()
    db.refresh(log)

    return log