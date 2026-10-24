from backend.database import SessionLocal
from backend.models import User, Document
from backend.authorization import authorize_document_access


db = SessionLocal()

try:
    # Get Alice from the database
    alice = db.query(User).filter(
        User.email == "alice@trustvault.com"
    ).first()

    if not alice:
        print("Alice was not found.")
        exit()

    print("Alice found:")
    print("ID:", alice.id)
    print("Role:", alice.role)

    # Check whether Alice has any documents
    document = db.query(Document).filter(
        Document.owner_id == alice.id
    ).first()

    if not document:
        print("\nNo documents exist yet.")
        print("Authorization function is ready.")
    else:
        result = authorize_document_access(
            document_id=document.id,
            current_user=alice,
            required_permission="READ",
            db=db
        )

        print("\nAuthorization successful!")
        print("Document:", result.filename)

finally:
    db.close()