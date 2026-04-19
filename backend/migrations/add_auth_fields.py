"""
add_auth_fields.py
------------------
Standalone migration: adds email and password_hash columns to the
organizations table.

Run from the backend/ directory:
    python migrations/add_auth_fields.py

Two-step approach for NOT NULL columns on a live table:
    1. ADD COLUMN with a temporary DEFAULT so existing rows satisfy the
       NOT NULL constraint immediately.
    2. DROP DEFAULT so future inserts must supply the value explicitly.
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL not set in environment / .env", file=sys.stderr)
    sys.exit(1)

try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2-binary not installed.", file=sys.stderr)
    sys.exit(1)


def run() -> None:
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur = conn.cursor()

    # --- email column ---
    cur.execute("""
        ALTER TABLE organizations
            ADD COLUMN IF NOT EXISTS email VARCHAR(255) NOT NULL DEFAULT '';
    """)
    cur.execute("""
        ALTER TABLE organizations
            ALTER COLUMN email DROP DEFAULT;
    """)
    # Unique index (IF NOT EXISTS guards idempotency)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_organizations_email
            ON organizations (email)
            WHERE email <> '';
    """)

    # --- password_hash column ---
    cur.execute("""
        ALTER TABLE organizations
            ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NOT NULL DEFAULT '';
    """)
    cur.execute("""
        ALTER TABLE organizations
            ALTER COLUMN password_hash DROP DEFAULT;
    """)

    cur.close()
    conn.close()
    print("Migration complete: email and password_hash columns added to organizations.")


if __name__ == "__main__":
    run()
