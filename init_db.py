"""Initialize database and create admin user."""
import os
import time as _time

os.environ['TZ'] = 'Asia/Shanghai'
try:
    _time.tzset()
except AttributeError:
    pass

import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'blog.db')

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute('''CREATE TABLE articles (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    pinned INTEGER NOT NULL DEFAULT 0,
    hidden INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

c.execute('''CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    parent_id INTEGER DEFAULT NULL,
    pinned INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (article_id) REFERENCES articles(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

c.execute('''CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    avatar TEXT NOT NULL DEFAULT ''
)''')

# Indexes
c.execute('CREATE INDEX IF NOT EXISTS idx_comments_article ON comments(article_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(user_id)')

# Default admin
c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
          ('StarryFirefly', generate_password_hash('Aa115811'), 'admin'))

# Sample article
c.execute('''INSERT INTO articles (title, content, summary) VALUES (?, ?, ?)''', (
    '你好，世界！',
    '<p>这是我的第一篇博客文章。欢迎来到繁星绘流萤的个人博客！</p>'
    '<p>这里会记录我的学习、思考和生活的点滴。</p>',
    '第一篇博客文章，开启写作之旅。'
))

article_id = c.lastrowid

# Sample comments
c.execute('''INSERT INTO comments (article_id, user_id, author, content)
             VALUES (?, 1, 'StarryFirefly', '欢迎大家留言交流~')''', (article_id,))

conn.commit()
conn.close()
print(f'Database initialized at {DB_PATH}')
print('Admin account: StarryFirefly / Aa115811')
