"""Add performance indexes to the blog database (safe for existing DB)."""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'blog.db')
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

indexes = [
    ('idx_comments_article', 'comments', 'article_id'),
    ('idx_comments_parent', 'comments', 'parent_id'),
    ('idx_comments_user', 'comments', 'user_id'),
]

for name, table, col in indexes:
    try:
        c.execute(f'CREATE INDEX IF NOT EXISTS {name} ON {table}({col})')
        print(f'Created index {name}')
    except sqlite3.OperationalError as e:
        print(f'Skipped {name}: {e}')

conn.commit()
conn.close()
print('Index migration complete.')
