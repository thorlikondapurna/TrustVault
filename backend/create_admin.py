from getpass import getpass

from backend.database import SessionLocal
from backend.models import User
from backend.security import hash_password


def create_admin():
    db = SessionLocal()

    try:
        name = input("Enter admin name: ")
        email = input("Enter admin email: ")
        password = getpass("Enter admin password: ")

        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            print("A user with this email already exists.")
            return

        admin = User(
            name=name,
            email=email,
            password_hash=hash_password(password),
            role="ADMIN"
        )

        db.add(admin)
        db.commit()
        db.refresh(admin)

        print("\nAdmin created successfully!")
        print("Admin ID:", admin.id)
        print("Name:", admin.name)
        print("Email:", admin.email)
        print("Role:", admin.role)

    finally:
        db.close()


if __name__ == "__main__":
    create_admin()