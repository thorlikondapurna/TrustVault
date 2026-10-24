# TrustVault — Threat Model

## 1. Overview

TrustVault is a secure document-sharing system designed to protect documents from unauthorized access, modification, deletion, and download.

The main security principle is:

> The server must verify authorization for every document operation.

TrustVault uses authentication, role-based access control, document-level permissions, input validation, protected file storage, and an audit trail to reduce security risks.

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

## 3. Threats and Mitigations

### Threat 1: Broken Access Control / IDOR

**Threat:**  
An authenticated user may try to access another user's document by changing the document ID in the API request.

**Example attack:**

```text
GET /documents/2/download

### Threat 6: Oversized File Upload

**Threat:**  
An attacker may upload an extremely large file to consume server storage or resources.

**Mitigation:**

- TrustVault enforces a maximum upload size of 10 MB.
- Files exceeding the limit are rejected.
- The failed upload attempt is recorded in the audit log.

**Test coverage:**

`test_upload_rejects_file_larger_than_10mb`

---

### Threat 7: Unsupported File Type

**Threat:**  
An attacker may upload a file type that is not supported by the application.

**Mitigation:**

- TrustVault allows only approved file types.
- Unsupported MIME types are rejected.
- The rejected upload is recorded in the audit log.

**Test coverage:**

`test_upload_rejects_unsupported_file_type`

---

### Threat 8: Fake File Type / Content-Type Spoofing

**Threat:**  
An attacker may rename a malicious or invalid file and declare it as an allowed file type, such as a PDF.

For example, a file containing plain text could be uploaded while declaring:

```text
Content-Type: application/pdf

### Threat 9: Missing Audit Trail

**Threat:**  
A user may perform sensitive actions such as downloading, editing, deleting, granting, or revoking access without the activity being recorded.

This makes security incidents difficult to investigate.

**Mitigation:**

- TrustVault records important document operations in the audit log.
- Both successful and denied operations are recorded.
- Audit records include the user, document, action, result, and details.

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
An attacker who gains access to the audit records may try to modify or delete previous audit events.

**Mitigation:**

- Each audit record contains an `event_hash`.
- Each record stores the hash of the previous audit record in `previous_hash`.
- This creates a hash chain between audit events.
- Changing an earlier event causes the subsequent hash verification to fail.
- Automated tests verify the complete audit hash chain.

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

---

### Threat 14: Privilege Escalation

**Threat:**  
A lower-privileged user may attempt to perform actions reserved for another role.

For example, a viewer may attempt to perform owner-level document operations.

**Mitigation:**

- User roles are stored in the database.
- Sensitive operations verify the authenticated user's role and/or document ownership.
- Document permissions are checked on the server.
- Client-side restrictions are not trusted as a security boundary.

---

## 4. Security Design Principles

TrustVault follows these principles:

### Server-Side Authorization

Authorization decisions are made by the backend rather than trusting the frontend.

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