# TrustVault — Secure Document Sharing with a Real Audit Trail

TrustVault is a secure document-sharing application designed to demonstrate **server-side authorization, controlled document access, immediate permission revocation, secure file handling, and a tamper-evident audit trail**.

The project was developed for a security-focused hackathon with an emphasis on preventing unauthorized document access and proving security behavior through automated tests.

---

## 🔐 Key Features

- JWT-based authentication
- Password hashing using Argon2
- Three user roles:
  - `ADMIN`
  - `OWNER`
  - `VIEWER`
- Secure document upload
- File type and file-size validation
- PDF, TXT, JPG/JPEG and PNG support
- Per-document `READ` and `EDIT` permissions
- Grant and revoke document access
- Immediate permission revocation
- Secure document downloads
- Server-side authorization on every document operation
- Document search by:
  - Filename
  - Category
  - Owner
  - Date range
- Admin audit-log viewing
- Audit logs for successful and refused operations
- Hash-linked audit trail for tamper detection
- Protection against direct storage access
- Automated authorization and security tests
- Simple browser-based frontend

---

## 🛡️ Security Design

TrustVault follows a **server-side security model**.

The frontend only controls what buttons are displayed. It is **not trusted for authorization**.

Every protected document operation is checked by the backend before the operation is performed.

### Authorization flow

```text
User Request
     ↓
JWT Authentication
     ↓
Identify Current User
     ↓
Find Requested Document
     ↓
Check Ownership / Permission
     ↓
Allow or Deny Operation
     ↓
Create Audit Record
```

This prevents users from bypassing the frontend by directly calling API endpoints.

---

## 👥 User Roles

### ADMIN

Administrators can access the administrative audit functionality.

The admin role does not automatically provide document-reading permission. This follows the principle of **least privilege**.

### OWNER

Document owners can:

- Upload documents
- View their documents
- Download documents
- Edit documents
- Delete documents
- Grant `READ` permission
- Grant `EDIT` permission
- Revoke permissions

### VIEWER

Viewers can access documents only when permission has been explicitly granted.

`READ` permission allows:

- Viewing/downloading the document

`EDIT` permission allows:

- Viewing/downloading
- Updating the document

A viewer cannot delete a document or manage its permissions.

---

## 📂 Project Structure

```text
TrustVault/
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── security.py
│   ├── auth.py
│   ├── dependencies.py
│   ├── authorization.py
│   ├── audit.py
│   ├── create_tables.py
│   ├── create_admin.py
│   └── ...
│
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── style.css
│   ├── app.js
│   └── dashboard.js
│
├── tests/
│   ├── test_authorization.py
│   └── test_audit_integrity.py
│
├── database/
│   ├── migrate_audit_hash.py
│   ├── backfill_audit_hashes.py
│   └── verify_audit_hashes.py
│
├── storage/
│
├── THREATS.md
├── PROMPTS.md
├── README.md
├── requirements.txt
├── .gitignore
└── .env
```

---

## 🗄️ Database Design

TrustVault uses PostgreSQL.

### Users

Stores application users and their roles.

```text
users
├── id
├── name
├── email
├── password_hash
├── role
└── created_at
```

### Documents

Stores document metadata.

```text
documents
├── id
├── filename
├── owner_id
├── category
├── storage_path
├── file_size
├── mime_type
├── created_at
├── updated_at
└── is_deleted
```

### Permissions

Stores document-specific access permissions.

```text
permissions
├── id
├── document_id
├── user_id
├── permission
├── granted_by
└── created_at
```

### Audit Logs

Stores security-related activity.

```text
audit_logs
├── id
├── user_id
├── document_id
├── action
├── result
├── details
├── timestamp
├── previous_hash
└── event_hash
```

---

## 🔑 Authentication

TrustVault uses JWT access tokens.

Passwords are never stored as plaintext.

Password processing uses:

```text
pwdlib + Argon2
```

After successful login, the server generates a JWT containing the authenticated user's ID.

Protected API requests require:

```text
Authorization: Bearer <token>
```

The backend validates the token and retrieves the current user from the database.

---

## 🔒 Authorization

Authorization is centralized in:

```text
backend/authorization.py
```

The backend checks:

1. Does the document exist?
2. Is the document deleted?
3. Is the current user the owner?
4. Does the current user have a permission record?
5. Does that permission allow the requested operation?

Example:

```text
READ
├── Owner → Allowed
├── READ → Allowed
├── EDIT → Allowed
└── No permission → Denied

EDIT
├── Owner → Allowed
├── EDIT → Allowed
├── READ → Denied
└── No permission → Denied
```

This provides protection against **Broken Access Control / IDOR / BOLA-style attacks**.

---

## 🚫 Immediate Permission Revocation

TrustVault does not depend on permanent download links for document authorization.

Permission is checked against the database whenever a protected document operation occurs.

Therefore:

```text
Permission granted
      ↓
User can access document
      ↓
Owner revokes permission
      ↓
Next request checks database
      ↓
Access denied
```

This means revoked access does not remain valid simply because the user previously had permission.

---

## 📁 Secure File Storage

Uploaded files are stored in the application's storage directory and are **not exposed through a public static route**.

Users must access documents through protected API endpoints.

For example, attempting to access:

```text
/storage/<filename>
```

directly is blocked.

This prevents users from bypassing authorization by accessing the storage location directly.

---

## 📤 Upload Security

Uploaded files are validated on the server.

### Maximum file size

```text
10 MB
```

### Allowed types

```text
PDF
TXT
JPG/JPEG
PNG
```

The server checks the declared MIME type and validates file signatures for binary formats.

For example:

```text
PDF → %PDF
PNG → PNG signature
JPEG → JPEG signature
```

This helps prevent simple MIME-type spoofing.

---

## 🧾 Audit Trail

TrustVault records important security events, including:

- Document uploads
- Downloads
- Updates
- Deletions
- Permission grants
- Permission revocations
- Refused access attempts

Each audit record contains:

```text
previous_hash
event_hash
```

The event hash is calculated using SHA-256 and includes information from the previous audit record.

Conceptually:

```text
GENESIS
   ↓
Audit 1
   ↓
Audit 2
   ↓
Audit 3
   ↓
Audit 4
```

If an existing audit record is modified, the hash chain verification can detect the inconsistency.

---

## 🔎 Secure Search

Documents can be searched using:

- Filename
- Category
- Owner
- Start date
- End date

Search results are filtered according to the authenticated user's access.

A user should not receive document metadata merely because they know another document's ID.

This reduces **information leakage through search**.

---

## 🧪 Automated Security Tests

The project includes automated tests covering important security requirements.

Current test suite:

```text
11 passed
```

The tests cover scenarios including:

- Unauthorized document access
- Unauthorized downloads
- Revoked access
- Unauthorized deletion
- Direct storage access
- Oversized file uploads
- Unsupported file types
- Fake PDF content
- Read-only users attempting edits
- Authorized editing
- Audit hash-chain integrity

Run the tests with:

```powershell
pytest -q
```

Expected result:

```text
11 passed
```

---

## ⚙️ Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- JWT
- pwdlib / Argon2

### Frontend

- HTML
- CSS
- JavaScript

### Testing

- Pytest
- FastAPI TestClient

### Security

- JWT authentication
- Password hashing
- Server-side authorization
- File validation
- SHA-256 audit hash chain
- Least-privilege access control

---

## 🚀 Local Setup

### 1. Clone the repository

```powershell
git clone https://github.com/thorlikondapurna/TrustVault.git
cd TrustVault
```

### 2. Create a virtual environment

```powershell
python -m venv venv
```

Activate it:

```powershell
venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

Create:

```text
.env
```

Example:

```text
DATABASE_USER=postgres
DATABASE_PASSWORD=YOUR_POSTGRES_PASSWORD
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=trustvault

JWT_SECRET_KEY=YOUR_RANDOM_SECRET
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
```

Do not commit `.env` to GitHub.

---

## 🗃️ PostgreSQL Setup

Create a PostgreSQL database named:

```text
trustvault
```

Make sure PostgreSQL is running before starting the application.

Create the database tables:

```powershell
python -m backend.create_tables
```

---

## 👤 Create an Administrator

Run:

```powershell
python -m backend.create_admin
```

The script asks for administrator information interactively.

Do not publish the administrator password in the repository.

---

## ▶️ Start the Backend

From the project root:

```powershell
uvicorn backend.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

FastAPI interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 🌐 Start the Frontend

Open another terminal in the project root.

Activate the virtual environment if necessary:

```powershell
venv\Scripts\activate
```

Run:

```powershell
python -m http.server 5500 --directory frontend
```

Open:

```text
http://127.0.0.1:5500
```

---

## 🔌 Important API Endpoints

### Authentication

```text
POST /register
POST /login
```

### Documents

```text
POST   /documents/upload
GET    /documents
GET    /documents/{document_id}/download
PUT    /documents/{document_id}
DELETE /documents/{document_id}
```

### Permissions

```text
POST /documents/{document_id}/permissions
POST /documents/{document_id}/permissions/revoke
```

### Administration

```text
GET /admin/audit-logs
```

The complete interactive API specification is available through FastAPI Swagger:

```text
/docs
```

---

## 🧪 Security Testing Philosophy

The security tests are designed around the assumption that a malicious user may bypass the frontend completely.

For example:

```text
Frontend
   ↓
Hidden Edit button
```

is **not considered security**.

Instead:

```text
Attacker
   ↓
Direct API request
   ↓
Backend authorization
   ↓
Permission check
   ↓
403 Forbidden
```

The server is therefore the final authority for every protected operation.

---

## 🛡️ Threat Model

The project includes a dedicated threat model:

```text
THREATS.md
```

It covers threats including:

- Broken access control / IDOR
- Unauthorized modification
- Unauthorized deletion
- Access after revocation
- Direct storage access
- Oversized uploads
- Unsupported file types
- Content-type spoofing
- Missing audit logs
- Audit-log tampering
- Search information leakage
- Weak authentication
- JWT manipulation
- Privilege escalation

---

## 🤖 AI Development Log

AI assistance used during development is documented in:

```text
PROMPTS.md
```

The document records development prompts, identified problems, corrections, and related project changes.

The goal is to maintain transparency about how AI-assisted development was used.

---

## 📌 Security Principles

TrustVault follows these principles:

### 1. Server-Side Authorization

The backend decides whether an operation is allowed.

### 2. Least Privilege

Users receive only the permissions required for their role and document access.

### 3. Immediate Revocation

Permission is checked during every protected operation.

### 4. Defense in Depth

Multiple security controls are used:

```text
Authentication
      +
Authorization
      +
File Validation
      +
Protected Storage
      +
Audit Logging
      +
Audit Integrity Verification
      +
Automated Tests
```

### 5. Fail Closed

When authorization cannot be established, the operation is denied rather than allowed.

---

## ⚠️ Development Notes

This project is a hackathon/educational security application.

Before production deployment, additional hardening should be considered, including:

- HTTPS-only deployment
- Secure cookie-based token handling where appropriate
- CSRF protection where cookie authentication is used
- Rate limiting
- Stronger upload-content inspection
- Malware scanning
- Database migrations using a migration framework
- Production secret management
- Centralized monitoring
- Backup and recovery procedures
- More extensive integration and penetration testing

---

## 📄 License

This project was created as part of a security-focused hackathon and is intended for educational and demonstration purposes.