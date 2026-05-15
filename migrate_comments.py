"""Add parent_id and pinned columns to comments table (safe for existing DB)."""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'blog.db')
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

try:
    c.execute('ALTER TABLE comments ADD COLUMN parent_id INTEGER DEFAULT NULL')
    print('Added parent_id column')
except sqlite3.OperationalError as e:
    if 'duplicate column' in str(e):
        print('parent_id already exists')
    else:
        raise

try:
    c.execute('ALTER TABLE comments ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0')
    print('Added pinned column')
except sqlite3.OperationalError as e:
    if 'duplicate column' in str(e):
        print('pinned already exists')
    else:
        raise

conn.commit()
conn.close()
print('Migration complete.')
