from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def login(email, password):
    response = client.post(
        "/login",
        json={
            "email": email,
            "password": password
        }
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def create_test_document():
    alice_token = login(
        "alice@trustvault.com",
        "StrongPassword123"
    )

    response = client.post(
        "/documents/upload",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        files={
            "file": (
                "authorization_test.txt",
                b"This is a test document for authorization testing.",
                "text/plain"
            )
        },
        data={
            "category": "Testing"
        }
    )

    assert response.status_code == 200

    return alice_token, response.json()["document_id"]


def test_unauthorized_user_cannot_access_document():
    response = client.get("/documents/999999/download")

    assert response.status_code in [401, 403, 404]


def test_bob_cannot_download_alice_document():
    alice_token, document_id = create_test_document()

    bob_token = login(
        "bob@trustvault.com",
        "BobPassword123"
    )

    response = client.get(
        f"/documents/{document_id}/download",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert response.status_code == 403

    # Cleanup
    client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {alice_token}"
        }
    )


def test_revoked_user_cannot_download_document():
    alice_token, document_id = create_test_document()

    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2,
            "permission": "READ"
        }
    )

    assert grant_response.status_code == 200

    bob_token = login(
        "bob@trustvault.com",
        "BobPassword123"
    )

    download_before_revoke = client.get(
        f"/documents/{document_id}/download",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert download_before_revoke.status_code == 200

    revoke_response = client.post(
        f"/documents/{document_id}/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2
        }
    )

    assert revoke_response.status_code == 200

    download_after_revoke = client.get(
        f"/documents/{document_id}/download",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert download_after_revoke.status_code == 403

    # Cleanup
    client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {alice_token}"
        }
    )


def test_non_owner_cannot_delete_document():
    alice_token, document_id = create_test_document()

    bob_token = login(
        "bob@trustvault.com",
        "BobPassword123"
    )

    response = client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {bob_token}"
        }
    )

    assert response.status_code == 403

    # Cleanup
    client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {alice_token}"
        }
    )


def test_direct_storage_access_is_blocked():
    response = client.get("/storage/imageWidgetExp.txt")

    assert response.status_code == 404


def test_upload_rejects_file_larger_than_10mb():
    alice_token = login(
        "alice@trustvault.com",
        "StrongPassword123"
    )

    large_file = b"A" * (11 * 1024 * 1024)

    response = client.post(
        "/documents/upload",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
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
    alice_token = login(
        "alice@trustvault.com",
        "StrongPassword123"
    )

    response = client.post(
        "/documents/upload",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
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
    alice_token = login(
        "alice@trustvault.com",
        "StrongPassword123"
    )

    response = client.post(
        "/documents/upload",
        headers={
            "Authorization": f"Bearer {alice_token}"
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
    alice_token, document_id = create_test_document()

    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2,
            "permission": "READ"
        }
    )

    assert grant_response.status_code == 200

    bob_token = login(
        "bob@trustvault.com",
        "BobPassword123"
    )

    response = client.put(
        f"/documents/{document_id}",
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

    assert response.status_code == 403

    # Cleanup
    client.post(
        f"/documents/{document_id}/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2
        }
    )

    client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {alice_token}"
        }
    )


def test_edit_permission_allows_editing():
    alice_token, document_id = create_test_document()

    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2,
            "permission": "EDIT"
        }
    )

    assert grant_response.status_code == 200

    bob_token = login(
        "bob@trustvault.com",
        "BobPassword123"
    )

    response = client.put(
        f"/documents/{document_id}",
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

    assert response.status_code == 200

    # Revoke access
    revoke_response = client.post(
        f"/documents/{document_id}/permissions/revoke",
        headers={
            "Authorization": f"Bearer {alice_token}"
        },
        json={
            "user_id": 2
        }
    )

    assert revoke_response.status_code == 200

    # Cleanup
    client.delete(
        f"/documents/{document_id}",
        headers={
            "Authorization": f"Bearer {alice_token}"
        }
    )

def test_public_user_cannot_register_as_admin():
    response = client.post(
        "/register",
        json={
            "name": "Fake Admin Test",
            "email": "fake-admin-test@example.com",
            "password": "TestPassword123",
            "role": "ADMIN"
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only OWNER or VIEWER registration is allowed"