from sqlalchemy import text
from backend.database import engine

with engine.begin() as connection:
    connection.execute(
        text("""
            ALTER TABLE audit_logs
            ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64),
            ADD COLUMN IF NOT EXISTS event_hash VARCHAR(64);
        """)
    )

print("Audit hash columns added successfully!")