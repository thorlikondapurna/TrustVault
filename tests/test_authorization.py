
from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_unauthorized_user_cannot_access_document():
    response = client.get("/documents/2/download")

    assert response.status_code in [401, 403]


def test_bob_cannot_download_alice_document():
    # Login as Bob
    login_response = client.post(
        "/login",
        json={
            "email": "bob@trustvault.com",
            "password": "BobPassword123"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Bob tries to directly access Alice's document.
    # The test assumes Bob has no permission for document 2.
    response = client.get(
        "/documents/2/download",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 403

def test_revoked_user_cannot_download_document():
    # Login as Alice
    alice_login = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert alice_login.status_code == 200

    alice_token = alice_login.json()["access_token"]

    # Grant Bob READ permission
    grant_response = client.post(
        "/documents/2/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5,
            "permission": "READ"
        }
    )

    assert grant_response.status_code == 200

    # Login as Bob
    bob_login = client.post(
        "/login",
        json={
            "email": "bob@trustvault.com",
            "password": "BobPassword123"
        }
    )

    assert bob_login.status_code == 200

    bob_token = bob_login.json()["access_token"]

    # Confirm Bob can download while permission exists
    download_before_revoke = client.get(
        "/documents/2/download",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert download_before_revoke.status_code == 200

    # Alice revokes Bob's permission
    revoke_response = client.post(
        "/documents/2/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5
        }
    )

    assert revoke_response.status_code == 200

    # Bob tries again after revocation
    download_after_revoke = client.get(
        "/documents/2/download",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert download_after_revoke.status_code == 403


def test_non_owner_cannot_delete_document():
    # Login as Bob
    bob_login = client.post(
        "/login",
        json={
            "email": "bob@trustvault.com",
            "password": "BobPassword123"
        }
    )

    assert bob_login.status_code == 200

    bob_token = bob_login.json()["access_token"]

    # Bob tries to delete Alice's document
    delete_response = client.delete(
        "/documents/2",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert delete_response.status_code == 403


def test_direct_storage_access_is_blocked():
    response = client.get("/storage/imageWidgetExp.txt")

    assert response.status_code == 404


def test_upload_rejects_file_larger_than_10mb():
    login_response = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    large_file = b"A" * (11 * 1024 * 1024)

    response = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={
            "file": (
                "large_file.txt",
                large_file,
                "text/plain"
            )
        },
        data={
            "category": "Other"
        }
    )

    assert response.status_code == 400


def test_upload_rejects_unsupported_file_type():
    login_response = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={
            "file": (
                "malicious.exe",
                b"This is not a valid document",
                "application/x-msdownload"
            )
        },
        data={
            "category": "Other"
        }
    )

    assert response.status_code == 400


def test_upload_rejects_fake_pdf_content():
    login_response = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.post(
        "/documents/upload",
        headers={
            "Authorization": f"Bearer {token}"
        },
        files={
            "file": (
                "fake.pdf",
                b"This is actually plain text, not a PDF",
                "application/pdf"
            )
        },
        data={
            "category": "Other"
        }
    )

    assert response.status_code == 400


def test_read_only_user_cannot_edit_document():
    # Login as Alice (document owner)
    alice_login = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert alice_login.status_code == 200

    alice_token = alice_login.json()["access_token"]

    # Give Bob READ permission
    grant_response = client.post(
        "/documents/2/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5,
            "permission": "READ"
        }
    )

    assert grant_response.status_code == 200

    # Login as Bob
    bob_login = client.post(
        "/login",
        json={
            "email": "bob@trustvault.com",
            "password": "BobPassword123"
        }
    )

    assert bob_login.status_code == 200

    bob_token = bob_login.json()["access_token"]

    # Bob tries to edit the document
    response = client.put(
        "/documents/2",
        headers={
            "Authorization": f"Bearer {bob_token}"
        },
        files={
            "file": (
                "unauthorized_edit.txt",
                b"Bob should not be able to edit this document",
                "text/plain"
            )
        }
    )

    # READ permission must NOT allow editing
    assert response.status_code == 403

    # Clean up Bob's permission
    revoke_response = client.post(
        "/documents/2/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5
        }
    )

    assert revoke_response.status_code == 200


def test_edit_permission_allows_editing():
    # Login as Alice (document owner)
    alice_login = client.post(
        "/login",
        json={
            "email": "alice@trustvault.com",
            "password": "StrongPassword123"
        }
    )

    assert alice_login.status_code == 200

    alice_token = alice_login.json()["access_token"]

    # Give Bob EDIT permission
    grant_response = client.post(
        "/documents/2/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5,
            "permission": "EDIT"
        }
    )

    assert grant_response.status_code == 200

    # Login as Bob
    bob_login = client.post(
        "/login",
        json={
            "email": "bob@trustvault.com",
            "password": "BobPassword123"
        }
    )

    assert bob_login.status_code == 200

    bob_token = bob_login.json()["access_token"]

    # Bob edits the document
    response = client.put(
        "/documents/2",
        headers={
            "Authorization": f"Bearer {bob_token}"
        },
        files={
            "file": (
                "updated_document.txt",
                b"This document was updated by an authorized editor.",
                "text/plain"
            )
        }
    )

    # EDIT permission should allow the operation
    assert response.status_code == 200

    # Remove Bob's permission so other tests are not affected
    revoke_response = client.post(
        "/documents/2/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 5
        }
    )

    assert revoke_response.status_code == 200