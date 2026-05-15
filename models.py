"""Database access layer."""
import os
import time as _time

os.environ['TZ'] = 'Asia/Shanghai'
try:
    _time.tzset()
except AttributeError:
    pass

import sqlite3
from datetime import datetime, timezone, timedelta

CST = timezone(timedelta(hours=8))


def now_cst():
    """Return current Beijing time as 'YYYY-MM-DD HH:MM:SS' string."""
    return datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')

DB_PATH = os.path.join(os.path.dirname(__file__), 'blog.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


# --- Articles ---

def _migrate_hidden_column(conn):
    """Add hidden column if it doesn't exist, backfill NULLs."""
    cols = [r[1] for r in conn.execute('PRAGMA table_info(articles)').fetchall()]
    if 'hidden' not in cols:
        conn.execute('ALTER TABLE articles ADD COLUMN hidden INTEGER DEFAULT 0')
        conn.commit()
    conn.execute('UPDATE articles SET hidden = 0 WHERE hidden IS NULL')
    conn.commit()


def get_articles(page=1, per_page=10, public_only=False):
    conn = get_db()
    _migrate_hidden_column(conn)
    offset = (page - 1) * per_page
    if public_only:
        rows = conn.execute(
            'SELECT * FROM articles WHERE hidden = 0 ORDER BY pinned DESC, created_at DESC LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()
        total = conn.execute('SELECT COUNT(*) FROM articles WHERE hidden = 0').fetchone()[0]
    else:
        rows = conn.execute(
            'SELECT * FROM articles ORDER BY id ASC LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()
        total = conn.execute('SELECT COUNT(*) FROM articles').fetchone()[0]
    conn.close()
    return [dict(r) for r in rows], total


def get_article(article_id):
    conn = get_db()
    _migrate_hidden_column(conn)
    row = conn.execute('SELECT * FROM articles WHERE id = ?', (article_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def find_available_id():
    """Return the smallest unused article ID (fill gap), or next sequential ID."""
    conn = get_db()
    row = conn.execute('SELECT id FROM articles ORDER BY id').fetchall()
    conn.close()
    existing = {r[0] for r in row}
    n = 1
    while n in existing:
        n += 1
    return n


def create_article(title, content, summary, created_at=None, article_id=None):
    conn = get_db()
    if article_id is not None:
        aid = article_id
    else:
        aid = find_available_id()
    conn.execute(
        'INSERT INTO articles (id, title, content, summary, created_at) VALUES (?, ?, ?, ?, ?)',
        (aid, title, content, summary, created_at or now_cst())
    )
    conn.commit()
    conn.close()
    return aid


def update_article(article_id, title, content, summary, created_at=None, new_id=None):
    conn = get_db()
    if new_id is not None and new_id != article_id:
        # Update foreign keys in comments first, then update article id
        conn.execute('UPDATE comments SET article_id = ? WHERE article_id = ?',
                     (new_id, article_id))
        conn.execute(
            'UPDATE articles SET id=?, title=?, content=?, summary=?, created_at=?, updated_at=? WHERE id=?',
            (new_id, title, content, summary, created_at or now_cst(), now_cst(), article_id)
        )
    else:
        conn.execute(
            'UPDATE articles SET title=?, content=?, summary=?, created_at=?, updated_at=? WHERE id=?',
            (title, content, summary, created_at or now_cst(), now_cst(), article_id)
        )
    conn.commit()
    conn.close()


def toggle_pin(article_id):
    conn = get_db()
    conn.execute(
        'UPDATE articles SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE id = ?',
        (article_id,)
    )
    conn.commit()
    conn.close()


def toggle_hidden(article_id):
    conn = get_db()
    conn.execute(
        'UPDATE articles SET hidden = CASE WHEN hidden = 1 THEN 0 ELSE 1 END WHERE id = ?',
        (article_id,)
    )
    conn.commit()
    conn.close()


def delete_article(article_id):
    conn = get_db()
    conn.execute('DELETE FROM comments WHERE article_id = ?', (article_id,))
    conn.execute('DELETE FROM articles WHERE id = ?', (article_id,))
    conn.commit()
    conn.close()


def search_articles(query, page=1, per_page=10):
    """Search articles by title or content, excluding hidden articles."""
    conn = get_db()
    _migrate_hidden_column(conn)
    offset = (page - 1) * per_page
    like = f'%{query}%'
    rows = conn.execute(
        'SELECT * FROM articles WHERE hidden = 0 AND (title LIKE ? OR content LIKE ?) '
        'ORDER BY pinned DESC, created_at DESC LIMIT ? OFFSET ?',
        (like, like, per_page, offset)
    ).fetchall()
    total = conn.execute(
        'SELECT COUNT(*) FROM articles WHERE hidden = 0 AND (title LIKE ? OR content LIKE ?)',
        (like, like)
    ).fetchone()[0]
    conn.close()
    return [dict(r) for r in rows], total


def is_image_used(image_url):
    """Check if an image URL is still referenced by any article."""
    conn = get_db()
    row = conn.execute(
        'SELECT COUNT(*) FROM articles WHERE content LIKE ?',
        (f'%{image_url}%',)
    ).fetchone()
    conn.close()
    return row[0] > 0


def get_image_articles(image_url):
    """Return list of {id, title} for articles that reference this image."""
    conn = get_db()
    rows = conn.execute(
        'SELECT id, title FROM articles WHERE content LIKE ?',
        (f'%{image_url}%',)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def rename_file_references(old_url, new_url):
    """Update all article content references from old_url to new_url."""
    conn = get_db()
    conn.execute(
        'UPDATE articles SET content = REPLACE(content, ?, ?) WHERE content LIKE ?',
        (old_url, new_url, f'%{old_url}%')
    )
    conn.commit()
    conn.close()


# --- Comments ---

def get_comments(article_id):
    conn = get_db()
    rows = conn.execute(
        '''SELECT c.*, u.role as author_role, u.avatar as author_avatar
           FROM comments c JOIN users u ON c.user_id = u.id
           WHERE c.article_id = ?
           ORDER BY c.pinned DESC, c.created_at ASC''',
        (article_id,)
    ).fetchall()
    conn.close()
    all_comments = [dict(r) for r in rows]

    parents = []
    replies_map = {}
    for c in all_comments:
        if c['parent_id'] is None:
            parents.append(c)
            c['replies'] = []
        else:
            replies_map.setdefault(c['parent_id'], []).append(c)

    for p in parents:
        p['replies'] = replies_map.get(p['id'], [])

    return parents


def get_comment(comment_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_comment(article_id, user_id, author, content, parent_id=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO comments (article_id, user_id, author, content, parent_id, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (article_id, user_id, author, content, parent_id, now_cst())
    )
    conn.commit()
    conn.close()


def get_all_comments():
    conn = get_db()
    rows = conn.execute(
        '''SELECT c.*, a.title as article_title
           FROM comments c JOIN articles a ON c.article_id = a.id
           ORDER BY c.pinned DESC, c.created_at DESC'''
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def toggle_comment_pin(comment_id):
    conn = get_db()
    conn.execute(
        'UPDATE comments SET pinned = CASE WHEN pinned = 1 THEN 0 ELSE 1 END WHERE id = ?',
        (comment_id,)
    )
    conn.commit()
    conn.close()


def update_comment(comment_id, content, created_at=None):
    conn = get_db()
    if created_at:
        conn.execute(
            'UPDATE comments SET content=?, created_at=? WHERE id=?',
            (content, created_at, comment_id)
        )
    else:
        conn.execute('UPDATE comments SET content=? WHERE id=?', (content, comment_id))
    conn.commit()
    conn.close()


def delete_comment(comment_id):
    conn = get_db()
    # Delete replies first
    conn.execute('DELETE FROM comments WHERE parent_id = ?', (comment_id,))
    conn.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    conn.commit()
    conn.close()


# --- Users ---

def get_user_by_username(username):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def find_available_user_id():
    """Return the smallest unused user ID (fill gap), or next sequential ID."""
    conn = get_db()
    rows = conn.execute('SELECT id FROM users ORDER BY id').fetchall()
    conn.close()
    existing = {r[0] for r in rows}
    n = 1
    while n in existing:
        n += 1
    return n


def create_user(username, password_hash, role='user', user_id=None):
    conn = get_db()
    try:
        if user_id is not None:
            uid = user_id
        else:
            uid = find_available_user_id()
        conn.execute(
            'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
            (uid, username, password_hash, role)
        )
        conn.commit()
        return uid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def change_password(user_id, new_password_hash):
    conn = get_db()
    conn.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (new_password_hash, user_id)
    )
    conn.commit()
    conn.close()


def update_avatar(user_id, avatar_path):
    conn = get_db()
    conn.execute('UPDATE users SET avatar = ? WHERE id = ?', (avatar_path, user_id))
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users():
    conn = get_db()
    rows = conn.execute('SELECT * FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user(user_id, username=None, role=None, avatar=None, new_user_id=None):
    conn = get_db()
    if username is not None:
        conn.execute('UPDATE users SET username = ? WHERE id = ?', (username, user_id))
    if role is not None:
        conn.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    if avatar is not None:
        conn.execute('UPDATE users SET avatar = ? WHERE id = ?', (avatar, user_id))
    if new_user_id is not None and new_user_id != user_id:
        conn.execute('UPDATE users SET id = ? WHERE id = ?', (new_user_id, user_id))
        conn.execute('UPDATE comments SET user_id = ? WHERE user_id = ?', (new_user_id, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM comments WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
