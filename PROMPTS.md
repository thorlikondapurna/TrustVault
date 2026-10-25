# TrustVault — AI Development Log

This document records how AI assistance was used during the development of TrustVault.

Each entry documents:

- The date
- The prompt/request given to AI
- The AI assistance received
- What was incorrect, incomplete, or needed improvement
- What was changed or implemented by the developer
- The related Git commit

AI was used as a development assistant. The final implementation, testing, debugging, security decisions, and verification were performed by the developer.

---

## Entry 1 — Project Architecture and Database Design

**Date:** 2026-10-24

### Prompt

> I need to build TrustVault, a secure document-sharing application for a hackathon. It needs authentication, at least three roles, document-level permissions, secure file storage, audit logging, search, and automated security tests. Suggest a suitable architecture and database design using Python, FastAPI, PostgreSQL, and SQLAlchemy.

### AI Assistance

AI suggested a FastAPI backend with PostgreSQL and SQLAlchemy and proposed separate database tables for:

- Users
- Documents
- Permissions
- Audit logs

The suggested design included user roles such as ADMIN, OWNER, and VIEWER, document ownership, document-level READ/EDIT permissions, and audit records for document and permission operations.

### What Needed Improvement

The initial design was a starting point and needed to be adapted to the actual TrustVault requirements.

In particular, the implementation needed to ensure that:

- Permissions were checked on every request.
- Revoked permissions took effect immediately.
- Unauthorized users could not access documents through alternate routes.
- Audit records included denied attempts.
- Audit logs could be checked for tampering.

### What I Implemented

I created the SQLAlchemy models for:

- `User`
- `Document`
- `Permission`
- `AuditLog`

I also created the PostgreSQL database and generated the database tables.

### Commit

Initial implementation:

[TrustVault initial implementation commit](https://github.com/thorlikondapurna/TrustVault/commit/429ebe7)

---

## Entry 2 — Authentication and Password Security

**Date:** 2026-10-24

### Prompt

> Help me implement secure authentication for a FastAPI application using JWT tokens, password hashing, environment variables, and database-backed users. Explain the implementation in a beginner-friendly way.

### AI Assistance

AI suggested:

- Password hashing using Argon2 through `pwdlib`
- JWT access tokens
- Environment variables for the JWT secret
- A FastAPI dependency to retrieve the currently authenticated user
- Token expiration
- Database lookup of the user associated with the JWT

### What Needed Improvement

The authentication implementation had to be connected to the actual TrustVault database models and environment configuration.

I also needed to make sure that:

- The JWT secret was not hardcoded.
- Passwords were never stored as plaintext.
- Expired or invalid tokens were rejected.
- The authenticated user was retrieved from the database.

### What I Implemented

I created:

- `backend/security.py`
- `backend/auth.py`
- `backend/dependencies.py`

The application now hashes passwords with Argon2 and uses JWT tokens for authenticated API requests.

### Commit

Initial authentication implementation:

[TrustVault initial implementation commit](https://github.com/thorlikondapurna/TrustVault/commit/429ebe7)

---

## Entry 3 — Authorization and Access Control

**Date:** 2026-10-24

### Prompt

> Implement secure document authorization for TrustVault. The document owner should have access to their own document. Other users should only be able to access a document when they have the required READ or EDIT permission. The server must check authorization on every request, and unauthorized users must receive an error.

### AI Assistance

AI suggested creating a centralized authorization function that:

1. Finds the requested document.
2. Checks whether the document is deleted.
3. Allows the document owner to access their document.
4. Looks up the current user's permission.
5. Allows READ access for READ or EDIT permission.
6. Allows EDIT access only for EDIT permission.
7. Rejects users without sufficient permission.

### What Needed Improvement

The authorization logic had to match the exact security requirements of the hackathon.

I specifically needed to ensure that:

- Authorization was performed on the server.
- The frontend could not bypass the checks.
- Document IDs could not be used to access another user's document.
- READ permission could not be used for editing.
- Users without permission were rejected.
- Revocation would be reflected immediately.

### What I Implemented

I created:

`backend/authorization.py`

with the centralized function:

`authorize_document_access()`

This function is called before protected document operations.

I also tested unauthorized access, download restrictions, deletion restrictions, and READ versus EDIT permissions.

### Commit

Authorization and security tests:

[Secure frontend and authorization tests](https://github.com/thorlikondapurna/TrustVault/commit/94d4088)

---

## Entry 4 — Audit Trail and Tamper Detection

**Date:** 2026-10-24

### Prompt

> TrustVault requires an audit trail for uploads, downloads, changes, deletions, permission changes, and refused attempts. Design an audit logging system that also makes unauthorized modification of audit records detectable.

### AI Assistance

AI suggested storing audit events in an `AuditLog` table and using a hash chain.

Each audit record stores:

- The previous audit record's hash
- The current event data
- The SHA-256 hash of the current event

This creates a chain where changing an earlier event can cause later hash verification to fail.

### What Needed Improvement

The basic audit logging needed additional work to handle the existing audit records.

I needed to:

- Add `previous_hash` and `event_hash` columns.
- Create a migration.
- Backfill hashes for existing audit records.
- Create a verification test.
- Make sure denied operations were also logged.

### What I Implemented

I created:

- `backend/audit.py`
- `database/migrate_audit_hash.py`
- `database/backfill_audit_hashes.py`
- `database/verify_audit_hashes.py`
- `tests/test_audit_integrity.py`

The existing audit records were hashed and verified.

The automated integrity test verifies the complete audit hash chain.

The hash chain provides **tamper detection**: if an existing audit record is modified, the calculated hash chain no longer matches the stored values.

Denied operations are also recorded in the audit trail.

### Commit

Audit logging and verification improvements:

[Fix audit logging and production API URLs](https://github.com/thorlikondapurna/TrustVault/commit/880bd2c)

---

## Entry 5 — Security Testing and File Validation

**Date:** 2026-10-24

### Prompt

> Create automated security tests for TrustVault that prove unauthorized users cannot access documents, revoked users cannot download documents, non-owners cannot delete documents, direct storage access is blocked, and unsafe uploads are rejected.

### AI Assistance

AI helped identify security-focused test cases including:

- Unauthorized document access
- Unauthorized downloads
- Revoked permissions
- Unauthorized deletion
- Direct storage access
- Oversized files
- Unsupported file types
- Fake PDF content
- READ-only edit attempts
- Authorized EDIT access
- Audit hash-chain integrity
- Public users attempting to register as ADMIN

### What Needed Improvement

Some tests initially required adjustment to match the actual database state and existing document IDs.

For example, the EDIT permission test needed to:

1. Log in as Alice.
2. Grant Bob EDIT permission.
3. Log in as Bob.
4. Edit the document.
5. Revoke Bob's permission afterward so later tests were not affected.

The tests were also updated to create test documents dynamically instead of depending on a fixed document ID.

### What I Implemented

I created and refined:

`tests/test_authorization.py`

and:

`tests/test_audit_integrity.py`

The final automated security test suite passed:

```text
12 passed
```

The tests verify important security properties including authorization, permission revocation, document deletion restrictions, upload validation, direct storage protection, and audit hash-chain integrity.

### Commit

Security testing improvements:

[Add admin registration security test](https://github.com/thorlikondapurna/TrustVault/commit/8acf2b2)

---

## Entry 6 — README and Project Documentation

**Date:** 2026-10-24

### Prompt

> Help me create a professional README for TrustVault that explains the project, features, technology stack, project structure, security design, API endpoints, testing, and how to run the project.

### AI Assistance

AI helped organize the README into sections covering:

- Project overview
- Features
- Technology stack
- Project structure
- Security design
- How the application works
- API endpoints
- Testing
- Security documentation
- Running the project

### What Needed Improvement

The first pasted version contained incorrectly escaped Markdown characters and incomplete code blocks.

I replaced the content with correctly formatted Markdown so that it renders properly on GitHub.

### What I Implemented

I created the final `README.md`, saved it, committed it separately, and pushed it to GitHub.

### Commit

[README documentation commit](https://github.com/thorlikondapurna/TrustVault/commit/8d483d3)

---

## Summary of AI Usage

AI was used throughout development as a coding and documentation assistant.

The main areas where AI assistance was used were:

1. Project architecture and database design
2. Authentication and password security
3. Authorization and document access control
4. Audit logging and tamper detection
5. Automated security testing
6. Project documentation

The developer reviewed, modified, tested, debugged, and verified the generated suggestions before using them in the project.

The final implementation was tested locally using the TrustVault PostgreSQL database and automated Pytest security tests.

The final automated security test suite passed all 12 tests.