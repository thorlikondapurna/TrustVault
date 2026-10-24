from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.models import User, Document, Permission


def authorize_document_access(
    document_id: int,
    current_user: User,
    required_permission: str,
    db: Session
):
    # Find the document
    document = db.query(Document).filter(
        Document.id == document_id
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )
    if document.is_deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
    )

    # Document owner has full access
    if document.owner_id == current_user.id:
        return document

    # Check permission granted to this user
    permission = db.query(Permission).filter(
        Permission.document_id == document_id,
        Permission.user_id == current_user.id
    ).first()

    # No permission
    if not permission:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this document"
        )

    # READ permission
    if required_permission == "READ":
        if permission.permission in ["READ", "EDIT"]:
            return document

    # EDIT permission
    if required_permission == "EDIT":
        if permission.permission == "EDIT":
            return document

    # Permission is insufficient
    raise HTTPException(
        status_code=403,
        detail="Insufficient permission for this action"
    )