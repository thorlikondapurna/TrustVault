# TrustVault — Threat Model

## 1. Overview

TrustVault is a secure document-sharing system designed to protect documents from unauthorized access, modification, deletion, and download.

The main security principle is:

> **The server must verify authorization for every document operation.**

TrustVault uses authentication, role-based access control, document-level permissions, input validation, protected file storage, and an audit trail to reduce security risks.

---

## 2. Security Goals

TrustVault aims to provide:

- Confidentiality of documents
- Integrity of documents
- Controlled document access
- Immediate permission revocation
- Protection against unauthorized downloads
- Protection against unauthorized modification and deletion
- Secure file upload validation
- Traceable document activity through audit logs
- Protection against direct access to stored files

---

## 3. Threats and Mitigations

### Threat 1: Broken Access Control / IDOR

**Threat:**

An authenticated user may try to access another user's document by changing the document ID in an API request.

**Example attack:**

```text
GET /documents/2/download
```

An attacker may replace the document ID with another value to attempt to access a document they do not own.

**Mitigation:**

- The server checks the authenticated user on every document operation.
- Document ownership is checked.
- Document-level permissions are checked.
- Users cannot access documents merely by knowing their IDs.
- The frontend is not trusted for authorization decisions.

**Test coverage:**

- `test_bob_cannot_download_alice_document`
- `test_unauthorized_user_cannot_access_document`

---

### Threat 2: Unauthorized Document Download

**Threat:**

A user without READ or EDIT permission may attempt to download a private document.

**Mitigation:**

- Downloads require server-side authorization.
- Owners can download their documents.
- Users with READ or EDIT permission can download.
- Unauthorized users receive an authorization error.
- Download attempts are recorded in the audit trail.

**Test coverage:**

- `test_bob_cannot_download_alice_document`

---

### Threat 3: Unauthorized Document Modification

**Threat:**

A user with READ-only access or no access may attempt to modify a document.

**Mitigation:**

- Editing requires ownership or EDIT permission.
- READ permission does not allow modification.
- Authorization is checked by the backend before the file is changed.
- Failed modification attempts are recorded.

**Test coverage:**

- `test_read_only_user_cannot_edit_document`
- `test_edit_permission_allows_editing`

---

### Threat 4: Unauthorized Document Deletion

**Threat:**

A viewer or another unauthorized user may attempt to delete someone else's document.

**Mitigation:**

- Only the document owner can delete a document.
- The backend verifies document ownership.
- Client-side buttons are not treated as a security boundary.
- Denied deletion attempts are recorded in the audit trail.

**Test coverage:**

- `test_non_owner_cannot_delete_document`

---

### Threat 5: Permission Revocation Bypass

**Threat:**

A user may continue accessing a document after their permission has been revoked.

**Mitigation:**

- Permissions are checked against the current database state on every request.
- The system does not rely on previously granted permissions stored in the client.
- No permanent document access URL bypasses authorization.
- Revoked permissions immediately prevent future access.

**Test coverage:**

- `test_revoked_user_cannot_download_document`

---

### Threat 6: Oversized File Upload

**Threat:**

An attacker may upload an extremely large file to consume server storage or resources.

**Mitigation:**

- TrustVault enforces a maximum upload size of 10 MB.
- Files exceeding the limit are rejected.
- Failed upload attempts are recorded in the audit trail.

**Test coverage:**

`test_upload_rejects_file_larger_than_10mb`

---

### Threat 7: Unsupported File Type

**Threat:**

An attacker may upload a file type that is not supported by the application.

**Mitigation:**

- TrustVault allows only approved file types.
- Unsupported MIME types are rejected.
- Rejected upload attempts are recorded.

**Test coverage:**

`test_upload_rejects_unsupported_file_type`

---

### Threat 8: Fake File Type / Content-Type Spoofing

**Threat:**

An attacker may rename an invalid file and declare it as an allowed file type.

For example, a file containing plain text could be uploaded while declaring:

```text
Content-Type: application/pdf
```

**Mitigation:**

- The server validates the declared MIME type.
- The server also validates file signatures for supported binary formats.
- A file whose content does not match its declared type is rejected.

**Test coverage:**

`test_upload_rejects_fake_pdf_content`

---

### Threat 9: Missing Audit Trail

**Threat:**

A user may perform sensitive actions such as downloading, editing, deleting, granting, or revoking access without the activity being recorded.

This makes security incidents difficult to investigate.

**Mitigation:**

TrustVault records important document operations in the audit log.

Both successful and denied operations are recorded where applicable.

Audit records include:

- User
- Document
- Action
- Result
- Details
- Timestamp

**Protected actions include:**

- Upload
- Download
- Edit
- Delete
- Grant permission
- Revoke permission

---

### Threat 10: Audit Log Tampering

**Threat:**

An attacker with access to audit records may attempt to modify previous audit events.

**Mitigation:**

- Each audit record contains an `event_hash`.
- Each record stores the hash of the previous audit record in `previous_hash`.
- This creates a hash chain between audit events.
- Modifying an earlier event causes subsequent hash verification to fail.
- Automated tests verify the audit hash chain.

The hash chain provides **tamper detection**. It is not a replacement for restricting database access.

**Test coverage:**

`test_audit_hash_chain_is_valid`

---

### Threat 11: Information Leakage Through Search

**Threat:**

A user may try to use document search to discover documents belonging to other users.

For example, an unauthorized user could search by filename or owner and learn that a private document exists.

**Mitigation:**

- Search results are filtered according to the current user's authorization.
- Unauthorized documents are not returned.
- Document metadata is protected by the same access-control rules as document operations.

---

### Threat 12: Weak Authentication

**Threat:**

An attacker may attempt to access TrustVault without valid credentials or by using another user's credentials.

**Mitigation:**

- Users must authenticate before accessing protected API endpoints.
- Passwords are stored as password hashes rather than plaintext passwords.
- JWT access tokens are used for authenticated requests.
- Invalid or expired tokens are rejected.
- The server identifies the current user from the authenticated token.

---

### Threat 13: JWT Token Manipulation

**Threat:**

An attacker may try to modify a JWT token to impersonate another user or change their identity.

**Mitigation:**

- JWTs are digitally signed using a server-side secret key.
- The server verifies the JWT signature before accepting the token.
- The user ID is obtained from the verified token.
- Invalid or tampered tokens are rejected.
- JWT secrets are stored in environment variables rather than source code.

---

### Threat 14: Privilege Escalation

**Threat:**

A lower-privileged user may attempt to perform actions reserved for another role.

For example, a viewer may attempt to perform owner-level or administrator-level operations.

A particularly important case is attempting to create an ADMIN account through public registration.

**Mitigation:**

- User roles are stored in the database.
- Sensitive operations verify the authenticated user's role and/or document ownership.
- Document permissions are checked on the server.
- Client-side restrictions are not trusted as a security boundary.
- Public registration allows only `OWNER` or `VIEWER` roles.
- Public users cannot register themselves as `ADMIN`.
- Administrator accounts are created through a controlled process.

**Test coverage:**

`test_public_user_cannot_register_as_admin`

---

## 4. Security Design Principles

### Server-Side Authorization

Authorization decisions are made by the backend rather than trusting the frontend.

Every protected document operation performs an authorization check.

### Least Privilege

Users receive only the permissions required for their document access.

### Immediate Revocation

Permission changes are checked against the current database state, allowing revoked access to stop immediately.

### Defense in Depth

Multiple security controls are used together:

- Authentication
- Role-based access control
- Document-level permissions
- File validation
- Protected storage
- Audit logging
- Audit hash chaining
- Automated security tests

### Fail Closed

When authentication or authorization information is missing or invalid, access is denied rather than allowed.

### Protected Storage

Uploaded documents are stored outside the public frontend/static directory.

TrustVault does not expose the storage directory through a public static-file route. Document downloads go through an authenticated backend endpoint that performs authorization first.

**Test coverage:**

`test_direct_storage_access_is_blocked`