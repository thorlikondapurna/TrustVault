from datetime import datetime, timezone

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    Enum,
    Boolean
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


# =========================
# USER MODEL
# =========================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    role: Mapped[str] = mapped_column(
        Enum("ADMIN", "OWNER", "VIEWER", name="user_role"),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    documents: Mapped[list["Document"]] = relationship(
        back_populates="owner"
    )


# =========================
# DOCUMENT MODEL
# =========================

class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    storage_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    mime_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    owner: Mapped["User"] = relationship(
        back_populates="documents"
    )


# =========================
# PERMISSION MODEL
# =========================

class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        nullable=False
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False
    )

    permission: Mapped[str] = mapped_column(
        Enum("READ", "EDIT", name="permission_type"),
        nullable=False
    )

    granted_by: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


# =========================
# AUDIT LOG MODEL
# =========================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=True
    )

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id"),
        nullable=True
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    result: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    details: Mapped[str] = mapped_column(
        Text,
        nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    previous_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=True
    )

    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=True
    )