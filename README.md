# TrustVault

Secure document sharing with role-based access control, document permissions, file validation, and tamper-evident audit logging.

## Features

- User authentication with JWT
- Role-based access control
- Three user roles: Admin, Owner, and Viewer
- Secure document upload and storage
- Document-level READ and EDIT permissions
- Permission granting and revocation
- Immediate access revocation
- File type, size, and content validation
- Secure document search and filtering
- Audit logging for successful and denied actions
- Tamper-evident audit log using hash chaining
- Protection against unauthorized document access
- Automated security and authorization tests

## Technology Stack

- **Backend:** Python, FastAPI
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Authentication:** JWT
- **Password Hashing:** Argon2
- **API Documentation:** FastAPI / Swagger UI
- **Testing:** Pytest
- **Version Control:** Git and GitHub

## Project Structure

```text
TrustVault/
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── schemas.py
│   ├── database.py
│   ├── security.py
│   ├── auth.py
│   ├── dependencies.py
│   ├── authorization.py
│   └── audit.py
├── tests/
│   ├── test_authorization.py
│   └── test_audit_integrity.py
├── database/
├── storage/
├── frontend/
├── THREATS.md
├── PROMPTS.md
├── README.md
├── requirements.txt
└── .gitignore
```

## Security Design

TrustVault is designed with security as a core requirement.

### Server-Side Authorization

Every document operation is checked on the server before access is allowed. The application does not rely on the frontend to enforce permissions.

### Least Privilege

Users receive only the permissions required for their role and for individual documents.

### Immediate Revocation

When a document permission is revoked, the authorization check immediately reflects the change. Previously granted access cannot be reused to bypass the current permission state.

### Secure File Storage

Uploaded documents are stored outside publicly accessible static routes. Direct access to storage files is blocked.

### File Validation

Uploaded files are validated using:

- Allowed MIME types
- Maximum file size
- File signature / magic-byte validation

### Audit Trail

Important document and permission operations are recorded in the audit log, including denied attempts.

Audit records use hash chaining to make unauthorized modification easier to detect.

### Fail Closed

If authorization cannot be established, access is denied rather than allowed by default.

## How It Works

1. A user registers and logs in.
2. The server authenticates the user and issues a JWT access token.
3. The user uploads a document.
4. The document is stored securely and its metadata is saved in PostgreSQL.
5. The document owner can grant READ or EDIT permission to another user.
6. Every document request is checked against the current user's permissions.
7. Unauthorized requests are rejected by the server.
8. Permission revocation takes effect immediately.
9. Important actions and denied attempts are recorded in the audit log.
10. Administrators can review document activity and permission changes.

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/register` | Register a new user |
| POST | `/login` | Authenticate a user and receive a JWT token |

### Documents

| Method | Endpoint | Description |
|---|---|---|
| POST | `/documents/upload` | Upload a document |
| GET | `/documents` | Search and list authorized documents |
| GET | `/documents/{document_id}/download` | Download an authorized document |
| PUT | `/documents/{document_id}` | Edit a document with EDIT permission |
| DELETE | `/documents/{document_id}` | Delete a document when authorized |

### Permissions

| Method | Endpoint | Description |
|---|---|---|
| POST | `/documents/{document_id}/permissions` | Grant READ or EDIT permission |
| POST | `/documents/{document_id}/permissions/revoke` | Revoke a user's permission |

### Administration

| Method | Endpoint | Description |
|---|---|---|
| GET | `/admin/audit-logs` | View document activity and permission-related audit logs |

## Testing

TrustVault includes automated tests for security-critical functionality.

The test suite verifies:

- Unauthorized users cannot access another user's documents.
- Unauthorized users cannot download protected documents.
- Revoked users cannot access documents.
- Non-owners cannot delete documents.
- Direct storage access is blocked.
- Oversized files are rejected.
- Unsupported file types are rejected.
- Fake file content is rejected.
- READ-only users cannot edit documents.
- Users with EDIT permission can edit documents.
- Audit log hash-chain integrity is maintained.

Run the tests with:

```bash
pytest -q
```

Expected result:

```text
11 passed
```

## Security Documentation

The project includes a threat model describing potential security risks and the controls used to reduce them.

See:

- [THREATS.md](THREATS.md) — Threat model and security controls
- [PROMPTS.md](PROMPTS.md) — AI-assisted development record

## Running the Project

### 1. Clone the repository

```bash
git clone https://github.com/thorlikondapurna/TrustVault.git
cd TrustVault
```

### 2. Create and activate the virtual environment

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root and configure the PostgreSQL database and JWT settings.

Example:

```env
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=trustvault

JWT_SECRET_KEY=your_secret_key
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
```

Never commit the real `.env` file or real credentials to GitHub.

### 5. Start the FastAPI server

```powershell
uvicorn backend.main:app --reload
```

The API will be available at:

`http://127.0.0.1:8000`

Interactive API documentation is available at:

`http://127.0.0.1:8000/docs`