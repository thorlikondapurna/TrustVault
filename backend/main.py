import os
import uuid

from typing import Optional
from datetime import date
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from fastapi.responses import FileResponse

from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User, Document, Permission, AuditLog
from backend.schemas import (
    UserRegister,
    UserLogin,
    PermissionRequest,
    RevokePermissionRequest
)
from backend.security import hash_password, verify_password
from backend.auth import create_access_token
from backend.dependencies import get_current_user
from backend.authorization import authorize_document_access
from backend.audit import create_audit_log


app = FastAPI(
    title="TrustVault",
    description="Secure document sharing with a real audit trail",
    version="1.0.0"
)


@app.get("/")
def home():
    return {"message": "Welcome to TrustVault"}


@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return {
        "user_id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role
    }

@app.post("/register")
def register_user(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    # Only OWNER and VIEWER can register publicly
    allowed_roles = {"OWNER", "VIEWER"}

    if user_data.role.upper() not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Only OWNER or VIEWER registration is allowed"
        )

    # Check whether the email already exists
    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Create user
    new_user = User(
        name=user_data.name,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        role=user_data.role.upper()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "role": new_user.role
    }

@app.post("/login")
def login_user(
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    # Find user by email
    user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    # Do not reveal whether the email exists
    if not user or not verify_password(
        user_data.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    # Create JWT token
    token = create_access_token(user.id)

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer"
    }

def validate_file_signature(file_data: bytes, content_type: str) -> bool:
    signatures = {
        "application/pdf": b"%PDF",
        "image/jpeg": b"\xff\xd8\xff",
        "image/png": b"\x89PNG\r\n\x1a\n",
    }

    if content_type == "text/plain":
        return True

    expected_signature = signatures.get(content_type)

    if expected_signature is None:
        return False

    return file_data.startswith(expected_signature)

@app.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    category: str = "Other",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Allowed file types
    allowed_types = {
        "application/pdf",
        "text/plain",
        "image/jpeg",
        "image/png"
    }

    # Maximum file size: 10 MB
    max_file_size = 10 * 1024 * 1024

    # Validate MIME type
    if file.content_type not in allowed_types:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="UPLOAD",
            result="DENIED",
            details=f"Unsupported file type: {file.content_type}"
        )

        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    # Read file
    file_data = await file.read()

        # Validate file content using magic bytes
    if not validate_file_signature(file_data, file.content_type):
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="UPLOAD",
            result="DENIED",
            details="File content does not match declared file type"
        )

        raise HTTPException(
            status_code=400,
            detail="File content does not match declared file type"
        )
    
    # Validate file size
    if len(file_data) > max_file_size:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="UPLOAD",
            result="DENIED",
            details="File exceeds 10 MB limit"
        )

        raise HTTPException(
            status_code=400,
            detail="File size exceeds 10 MB"
        )

    # Create secure storage filename
    file_extension = os.path.splitext(file.filename)[1]
    secure_filename = f"{uuid.uuid4()}{file_extension}"

    storage_directory = "storage"
    os.makedirs(storage_directory, exist_ok=True)

    storage_path = os.path.join(
        storage_directory,
        secure_filename
    )

    # Save file
    with open(storage_path, "wb") as output_file:
        output_file.write(file_data)

    # Create database record
    document = Document(
        filename=file.filename,
        owner_id=current_user.id,
        category=category,
        storage_path=storage_path,
        file_size=len(file_data),
        mime_type=file.content_type
    )

    db.add(document)
    db.commit()
    db.refresh(document)

    # Audit successful upload
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document.id,
        action="UPLOAD",
        result="SUCCESS",
        details=f"Uploaded file: {file.filename}"
    )

    return {
        "message": "Document uploaded successfully",
        "document_id": document.id,
        "filename": document.filename,
        "category": document.category,
        "size": document.file_size
    }

@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Check authorization BEFORE accessing the file
        document = authorize_document_access(
            document_id=document_id,
            current_user=current_user,
            required_permission="READ",
            db=db
        )

    except HTTPException as e:
        # Record denied download attempt
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="DOWNLOAD",
            result="DENIED",
            details=e.detail
        )

        raise

    # Verify that the stored file actually exists
    if not os.path.isfile(document.storage_path):
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="DOWNLOAD",
            result="FAILED",
            details="Stored file not found"
        )

        raise HTTPException(
            status_code=404,
            detail="Stored file not found"
        )

    # Record successful download
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document.id,
        action="DOWNLOAD",
        result="SUCCESS",
        details=f"Downloaded file: {document.filename}"
    )

    return FileResponse(
        path=document.storage_path,
        filename=document.filename,
        media_type=document.mime_type
    )


@app.post("/documents/{document_id}/permissions")
def grant_permission(
    document_id: int,
    permission_data: PermissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
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

    # Only the document owner can grant permissions
    if document.owner_id != current_user.id:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="GRANT_PERMISSION",
            result="DENIED",
            details="Only the document owner can grant permissions"
        )

        raise HTTPException(
            status_code=403,
            detail="Only the document owner can grant permissions"
        )

    # Validate permission type
    permission_type = permission_data.permission.upper()

    if permission_type not in {"READ", "EDIT"}:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="GRANT_PERMISSION",
            result="DENIED",
            details="Invalid permission type"
        )

        raise HTTPException(
            status_code=400,
            detail="Permission must be READ or EDIT"
        )

    # Check that target user exists
    target_user = db.query(User).filter(
        User.id == permission_data.user_id
    ).first()

    if not target_user:
        raise HTTPException(
            status_code=404,
            detail="Target user not found"
        )

    # Owner does not need a separate permission
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Document owner already has full access"
        )

    # Check existing permission
    existing_permission = db.query(Permission).filter(
        Permission.document_id == document_id,
        Permission.user_id == target_user.id
    ).first()

    if existing_permission:
        existing_permission.permission = permission_type
        existing_permission.granted_by = current_user.id

        db.commit()

        action = "UPDATE_PERMISSION"
        message = "Permission updated successfully"

    else:
        new_permission = Permission(
            document_id=document_id,
            user_id=target_user.id,
            permission=permission_type,
            granted_by=current_user.id
        )

        db.add(new_permission)
        db.commit()

        action = "GRANT_PERMISSION"
        message = "Permission granted successfully"

    # Audit the successful permission change
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document_id,
        action=action,
        result="SUCCESS",
        details=(
            f"{permission_type} permission for "
            f"user {target_user.id}"
        )
    )

    return {
        "message": message,
        "document_id": document_id,
        "user_id": target_user.id,
        "permission": permission_type
    }

@app.put("/documents/{document_id}")
async def edit_document(
    document_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # EDIT permission is required
        document = authorize_document_access(
            document_id=document_id,
            current_user=current_user,
            required_permission="EDIT",
            db=db
        )

    except HTTPException as e:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="EDIT",
            result="DENIED",
            details=e.detail
        )

        raise

    # Validate file type
    allowed_types = {
        "application/pdf",
        "text/plain",
        "image/jpeg",
        "image/png"
    }

    if file.content_type not in allowed_types:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="EDIT",
            result="DENIED",
            details=f"Unsupported file type: {file.content_type}"
        )

        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    # Read the replacement file
    file_data = await file.read()

    # 10 MB limit
    max_file_size = 10 * 1024 * 1024

    if len(file_data) > max_file_size:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="EDIT",
            result="DENIED",
            details="File exceeds 10 MB limit"
        )

        raise HTTPException(
            status_code=400,
            detail="File size exceeds 10 MB"
        )

    # Replace the existing stored file
    with open(document.storage_path, "wb") as output_file:
        output_file.write(file_data)

    # Update document metadata
    document.filename = file.filename
    document.file_size = len(file_data)
    document.mime_type = file.content_type

    db.commit()
    db.refresh(document)

    # Audit successful edit
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document.id,
        action="EDIT",
        result="SUCCESS",
        details=f"Edited file: {document.filename}"
    )

    return {
        "message": "Document updated successfully",
        "document_id": document.id,
        "filename": document.filename,
        "size": document.file_size
    }

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find the document
    document = db.query(Document).filter(
        Document.id == document_id
    ).first()

    if not document:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="DELETE",
            result="DENIED",
            details="Document not found"
        )

        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    # Only the document owner can delete the document
    if document.owner_id != current_user.id:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="DELETE",
            result="DENIED",
            details="Only the document owner can delete this document"
        )

        raise HTTPException(
            status_code=403,
            detail="Only the document owner can delete this document"
        )

    # Check if already deleted
    if document.is_deleted:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="DELETE",
            result="DENIED",
            details="Document is already deleted"
        )

        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    # Delete the physical file
    if os.path.isfile(document.storage_path):
        os.remove(document.storage_path)

    # Mark the document as deleted
    document.is_deleted = True

    db.commit()

    # Record successful deletion
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document.id,
        action="DELETE",
        result="SUCCESS",
        details=f"Deleted file: {document.filename}"
    )

    return {
        "message": "Document deleted successfully",
        "document_id": document.id
    }

@app.post("/documents/{document_id}/permissions/revoke")
def revoke_permission(
    document_id: int,
    revoke_data: RevokePermissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find the document
    document = db.query(Document).filter(
        Document.id == document_id
    ).first()

    if not document or document.is_deleted:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="REVOKE_PERMISSION",
            result="DENIED",
            details="Document not found"
        )

        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    # Only the document owner can revoke permissions
    if document.owner_id != current_user.id:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="REVOKE_PERMISSION",
            result="DENIED",
            details="Only the document owner can revoke permissions"
        )

        raise HTTPException(
            status_code=403,
            detail="Only the document owner can revoke permissions"
        )

    # Find the permission
    permission = db.query(Permission).filter(
        Permission.document_id == document_id,
        Permission.user_id == revoke_data.user_id
    ).first()

    if not permission:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            document_id=document_id,
            action="REVOKE_PERMISSION",
            result="DENIED",
            details="Permission not found"
        )

        raise HTTPException(
            status_code=404,
            detail="Permission not found"
        )

    # Remove the permission
    db.delete(permission)
    db.commit()

    # Record successful revocation
    create_audit_log(
        db=db,
        user_id=current_user.id,
        document_id=document_id,
        action="REVOKE_PERMISSION",
        result="SUCCESS",
        details=f"Revoked permission for user {revoke_data.user_id}"
    )

    return {
        "message": "Permission revoked successfully",
        "document_id": document_id,
        "user_id": revoke_data.user_id
    }

@app.get("/documents")
def list_documents(
    filename: Optional[str] = None,
    category: Optional[str] = None,
    owner_id: Optional[int] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Start with documents that are not deleted
    query = db.query(Document).filter(
        Document.is_deleted == False
    )

    # Only show documents the current user is allowed to see
    if current_user.role == "ADMIN":
        # Admin can see document metadata for auditing/search
        pass
    else:
        # User can see:
        # 1. Their own documents
        # 2. Documents where they have READ or EDIT permission
        query = query.outerjoin(
            Permission,
            Permission.document_id == Document.id
        ).filter(
            (Document.owner_id == current_user.id) |
            (
                (Permission.user_id == current_user.id) &
                (Permission.permission.in_(["READ", "EDIT"]))
            )
        )

    # Search by filename
    if filename:
        query = query.filter(
            Document.filename.ilike(f"%{filename}%")
        )

    # Search by category
    if category:
        query = query.filter(
            Document.category.ilike(f"%{category}%")
        )

    # Search by owner
    if owner_id:
        query = query.filter(
            Document.owner_id == owner_id
        )
    # Search by date
    if start_date:
        query = query.filter(
            Document.created_at >= start_date
        )

    if end_date:
        query = query.filter(
            Document.created_at < end_date.fromordinal(
                end_date.toordinal() + 1
            )
    )
    documents = query.all()

    return [
        {
            "id": document.id,
            "filename": document.filename,
            "owner_id": document.owner_id,
            "category": document.category,
            "file_size": document.file_size,
            "mime_type": document.mime_type,
            "created_at": document.created_at,
            "updated_at": document.updated_at
        }
        for document in documents
    ]

@app.get("/admin/audit-logs")
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Only administrators can view audit logs
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can view audit logs"
        )

    logs = db.query(AuditLog).order_by(
        AuditLog.timestamp.desc()
    ).all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "document_id": log.document_id,
            "action": log.action,
            "result": log.result,
            "details": log.details,
            "timestamp": log.timestamp
        }
        for log in logs
    ]
