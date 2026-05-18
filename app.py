"""Flask application entry point."""
import os
import time as _time

os.environ['TZ'] = 'Asia/Shanghai'
try:
    _time.tzset()
except AttributeError:
    pass  # Windows doesn't have tzset

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import models
import io
import json
import random
import re
import uuid

from PIL import Image, ImageDraw, ImageFont, ImageFilter

import secrets
import subprocess
from datetime import timedelta

app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
PER_PAGE = 10
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
AVATAR_DIR = os.path.join(os.path.dirname(__file__), 'static', 'avatars')
BG_DIR = os.path.join(os.path.dirname(__file__), 'static', 'bg')
THUMB_DIR = os.path.join(UPLOAD_DIR, 'thumbs')
ATTACH_DIR = os.path.join(UPLOAD_DIR, 'attachments')
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
VIDEO_EXTENSIONS = {'mp4', 'webm', 'mov'}
ATTACH_BLOCKED = set()  # 个人使用，不限制文件类型
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(BG_DIR, exist_ok=True)
os.makedirs(THUMB_DIR, exist_ok=True)
os.makedirs(ATTACH_DIR, exist_ok=True)


def get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False)


# --- 持久化密钥，防止重启后登录丢失 ---
def _load_secret_key():
    cfg = get_config()
    key = cfg.get('secret_key')
    if not key:
        key = secrets.token_hex(32)
        cfg['secret_key'] = key
        save_config(cfg)
    return key

app.secret_key = os.environ.get('SECRET_KEY', _load_secret_key())


# --- 静态文件版本号，解决浏览器缓存问题 ---
def _static_v(filename):
    """Return static URL with file mtime as cache buster."""
    fpath = os.path.join(os.path.dirname(__file__), 'static', filename)
    try:
        mtime = int(os.path.getmtime(fpath))
    except OSError:
        mtime = 0
    return f'/static/{filename}?v={mtime}'

app.jinja_env.globals['static_v'] = _static_v


def safe_filename(fname, base_dir):
    """Prevent path traversal: only allow filenames within base_dir."""
    fname = os.path.basename(fname)
    if '..' in fname or '/' in fname or '\\' in fname:
        return None
    fpath = os.path.join(base_dir, fname)
    real_base = os.path.realpath(base_dir)
    real_path = os.path.realpath(fpath)
    if not real_path.startswith(real_base + os.sep):
        return None
    return fname


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in VIDEO_EXTENSIONS


def allowed_media_file(filename):
    return allowed_file(filename) or is_video_file(filename)


def generate_video_thumbnail(video_path, thumb_dir, base_name):
    thumb_name = f'{base_name}.jpg'
    thumb_path = os.path.join(thumb_dir, thumb_name)
    try:
        result = subprocess.run([
            'ffmpeg', '-y', '-i', video_path,
            '-ss', '00:00:01', '-vframes', '1',
            '-vf', 'scale=360:-1',
            thumb_path
        ], capture_output=True, timeout=15)
        if os.path.exists(thumb_path):
            return thumb_name
        else:
            app.logger.warning(f'ffmpeg exited {result.returncode}: {result.stderr.decode()[:200]}')
    except FileNotFoundError:
        app.logger.info('ffmpeg not installed, using client-side thumbnails')
    except Exception as e:
        app.logger.warning(f'Video thumbnail failed: {e}')
    return None



# Image magic bytes for content-type validation
_IMG_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'png',
    b'\xff\xd8\xff': 'jpg',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
    b'RIFF': 'webp',   # + WEBP at offset 8
    b'BM': 'bmp',
}


def validate_image_content(file_storage):
    """Check that the file's magic bytes match a known image format.
    Returns (is_valid, detected_type)."""
    pos = file_storage.tell()
    header = file_storage.read(12)
    file_storage.seek(pos)
    if not header:
        return False, None
    for sig, ftype in _IMG_SIGNATURES.items():
        if header.startswith(sig):
            if ftype == 'webp':
                if len(header) >= 12 and header[8:12] == b'WEBP':
                    return True, 'webp'
                continue
            return True, ftype
    return False, None


IMG_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
VIDEO_RE = re.compile(r'<video[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

def extract_thumbnail(html_content):
    """Extract the first image URL from HTML content, return thumb if exists."""
    m = IMG_RE.search(html_content or '')
    if not m:
        return None
    url = m.group(1)
    if '/uploads/' in url:
        fname = url.rsplit('/', 1)[-1]
        base = fname.rsplit('.', 1)[0]
        # Thumb may be .jpg or .png regardless of original extension
        for try_ext in ('jpg', 'png', 'webp', 'gif'):
            thumb_path = os.path.join(THUMB_DIR, f'{base}.{try_ext}')
            if os.path.exists(thumb_path):
                return f'/static/uploads/thumbs/{base}.{try_ext}'
    return url


CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

CAPTCHA_FONT_PATHS = [
    # CentOS / Alibaba Cloud Linux
    '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/liberation/LiberationSans-Bold.ttf',
    '/usr/share/fonts/liberation/LiberationSans-Regular.ttf',
    '/usr/share/fonts/google-noto/NotoSans-Bold.ttf',
    # Debian / Ubuntu
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
    '/usr/share/fonts/truetype/freefont/FreeSansBold.ttf',
    '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
    '/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf',
    # Windows
    'C:\\Windows\\Fonts\\arial.ttf',
    'C:\\Windows\\Fonts\\arialbd.ttf',
    'arial.ttf',
]

FONT_SIZE = 56

def _load_captcha_font():
    for path in CAPTCHA_FONT_PATHS:
        if os.path.exists(path):
            return ImageFont.truetype(path, FONT_SIZE)
    return None

def generate_captcha_image(code):
    """Generate a CAPTCHA image for the given code, return PNG bytes."""
    w, h = 280, 80
    img = Image.new('RGB', (w, h), color='#f0f4f8')
    draw = ImageDraw.Draw(img)
    for _ in range(60):
        x, y = random.randint(0, w), random.randint(0, h)
        draw.point((x, y), fill=(random.randint(150, 200), random.randint(160, 210), random.randint(170, 220)))
    font = _load_captcha_font()
    for i, ch in enumerate(code):
        color = (random.randint(40, 100), random.randint(60, 130), random.randint(120, 200))
        if font:
            x = 10 + i * 68 + random.randint(-8, 8)
            y = random.randint(4, 14)
            draw.text((x, y), ch, fill=color, font=font)
        else:
            # Fallback: draw each char multiple times slightly offset to create visible bold text
            x = 10 + i * 68
            y = random.randint(8, 16)
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    draw.text((x + dx, y + dy), ch, fill=color, font=ImageFont.load_default())
    # Distortion lines
    for _ in range(2):
        x1, y1 = random.randint(0, w), random.randint(0, h)
        x2, y2 = random.randint(0, w), random.randint(0, h)
        draw.line((x1, y1, x2, y2), fill=(random.randint(100, 180), random.randint(120, 190), random.randint(140, 210)), width=1)
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf.read()


@app.route('/captcha.png')
def captcha_image():
    code = ''.join(random.choice(CAPTCHA_CHARS) for _ in range(4))
    session['captcha'] = code
    return app.response_class(generate_captcha_image(code), mimetype='image/png')


@app.after_request
def add_cache_headers(response):
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 2592000  # 30 days
        response.cache_control.public = True
        # Only use immutable on versioned assets (UUID filenames)
        if not request.path.endswith('.css'):
            response.cache_control.immutable = True
    return response


LAZY_IMG_RE = re.compile(r'<img(?![^>]*\bloading=)[^>]*>', re.IGNORECASE)

def add_lazy_loading(html):
    """Add loading='lazy' to <img> tags that don't already have a loading attribute."""
    return LAZY_IMG_RE.sub(lambda m: m.group(0)[:-1] + ' loading="lazy">', html or '')


ATTACH_MARKER_RE = re.compile(
    r'\[\[attachment:(.*?)::(.*?)::(.*?)\]\]',
    re.DOTALL
)

def render_attachment_markers(html):
    """Replace attachment markers with styled HTML cards."""
    def build_card(m):
        url   = m.group(1).strip()
        name  = m.group(2).strip()
        size  = m.group(3).strip()
        size_html = f'<span class="att-size">{size}</span>' if size else ''
        return (
            '<div class="attachment-card">'
            f'<a href="{url}" download="{name}" rel="noopener">'
            '<span class="att-icon">📎</span>'
            '<span class="att-info">'
            f'<span class="att-name">{name}</span>'
            f'{size_html}'
            '</span>'
            '<span class="att-dl-btn">⤓</span>'
            '</a>'
            '</div>'
        )
    return ATTACH_MARKER_RE.sub(build_card, html or '')


def count_comments(comments):
    """Recursively count comments including nested replies."""
    total = 0
    for c in comments:
        total += 1
        total += len(c.get('replies', []))
    return total


@app.context_processor
def inject_current_user():
    cfg = get_config()
    ctx = {
        'current_user': None,
        'bg_image': cfg.get('bg_image', ''),
        'bg_blur': cfg.get('bg_blur', 18),
        'profile_title': cfg.get('profile_title', ''),
        'profile_content': cfg.get('profile_content', ''),
        'site_title': cfg.get('site_title', '繁星绘流萤'),
        'site_subtitle': cfg.get('site_subtitle', '记录思考，分享生活'),
        'count_comments': count_comments,
        'csrf_token': generate_csrf_token(),
    }
    if 'user_id' in session:
        user = models.get_user_by_id(session['user_id'])
        ctx['current_user'] = user
    return ctx


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated


# --- CSRF protection ---

def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def csrf_required(f):
    """Validate CSRF token on POST/PUT/DELETE requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or token != session.get('csrf_token'):
                flash('请求已过期，请刷新页面后重试。')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# --- Rate limiter ---
_rate_limit_store = {}

def rate_limit(max_attempts=5, window=60):
    """Simple in-memory rate limiter. Returns True if rate limited."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            key = f'rate:{request.remote_addr}:{request.endpoint}'
            now = _time.time()
            entries = _rate_limit_store.get(key, [])
            entries = [t for t in entries if now - t < window]
            if len(entries) >= max_attempts:
                flash(f'请求过于频繁，请 {window} 秒后再试。')
                if request.endpoint == 'user_login':
                    return redirect(url_for('user_login'))
                return redirect(url_for('index'))
            entries.append(now)
            _rate_limit_store[key] = entries
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        if session.get('role') != 'admin':
            flash('需要管理员权限。')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# --- Public Routes ---

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    query = request.args.get('q', '').strip()
    if query:
        articles, total = models.search_articles(query, page, PER_PAGE)
    else:
        articles, total = models.get_articles(page, PER_PAGE, public_only=True)
    for a in articles:
        a['thumbnail'] = extract_thumbnail(a.get('content', ''))
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render_template('index.html', articles=articles,
                           page=page, total_pages=total_pages, query=query)


@app.route('/article/<int:article_id>')
def article(article_id):
    article = models.get_article(article_id)
    if not article:
        return render_template('404.html'), 404
    if article.get('hidden') == 1 and session.get('role') != 'admin':
        return render_template('404.html'), 404
    article['content'] = add_lazy_loading(article.get('content', ''))
    article['content'] = render_attachment_markers(article['content'])
    comments = models.get_comments(article_id)
    return render_template('article.html', article=article, comments=comments)


# --- Comment (requires login) ---

@app.route('/article/<int:article_id>/comment', methods=['POST'])
@login_required
@csrf_required
def add_comment(article_id):
    article = models.get_article(article_id)
    if not article:
        return render_template('404.html'), 404
    content = request.form.get('content', '').strip()
    parent_id = request.form.get('parent_id', type=int) or None
    if content:
        models.create_comment(article_id, session['user_id'],
                              session['username'], content, parent_id)
        flash('评论发布成功！')
    else:
        flash('请填写评论内容。')
    return redirect(url_for('article', article_id=article_id))


@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_comment(comment_id):
    comment = models.get_comment(comment_id)
    if not comment:
        return render_template('404.html'), 404
    if comment['user_id'] == session['user_id'] or session.get('role') == 'admin':
        models.delete_comment(comment_id)
        flash('评论已删除。')
    else:
        flash('你无权删除此评论。')
    return redirect(url_for('article', article_id=comment['article_id']))


@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
@csrf_required
def edit_comment(comment_id):
    comment = models.get_comment(comment_id)
    if not comment:
        return render_template('404.html'), 404
    if comment['user_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('你无权编辑此评论。')
        return redirect(url_for('article', article_id=comment['article_id']))
    content = request.form.get('content', '').strip()
    created_at = request.form.get('created_at', '').strip().replace('T', ' ') or None
    if content:
        models.update_comment(comment_id, content, created_at)
        flash('评论已更新。')
    next_url = request.form.get('next', '')
    # 防止开放重定向：仅允许站内相对路径
    if not next_url or not next_url.startswith('/') or next_url.startswith('//'):
        next_url = url_for('article', article_id=comment['article_id'])
    return redirect(next_url)


@app.route('/comment/<int:comment_id>/pin', methods=['POST'])
@admin_required
@csrf_required
def pin_comment(comment_id):
    comment = models.get_comment(comment_id)
    if comment:
        models.toggle_comment_pin(comment_id)
    return redirect(url_for('admin_comments'))


# --- User Registration & Login ---

@app.route('/user/register', methods=['GET', 'POST'])
@csrf_required
def user_register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    username = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        captcha = request.form.get('captcha', '').strip().upper()
        if not username or not password:
            flash('请填写用户名和密码。')
        elif len(username) < 2 or len(username) > 30:
            flash('用户名需要2-30个字符。')
        elif password != password2:
            flash('两次密码不一致。')
        elif len(password) < 6:
            flash('密码至少6位。')
        elif models.get_user_by_username(username):
            flash('该用户名已被注册。')
        elif not captcha or captcha != session.get('captcha', ''):
            flash('验证码错误。')
        else:
            pw_hash = generate_password_hash(password)
            if models.create_user(username, pw_hash):
                flash('注册成功！请登录。')
                return redirect(url_for('user_login'))
            else:
                flash('注册失败，请重试。')
    return render_template('user/register.html', last_username=username)


@app.route('/user/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=10, window=60)
@csrf_required
def user_login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = models.get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['avatar'] = user.get('avatar', '')
            flash(f'欢迎回来，{username}！')
            return redirect(url_for('index'))
        flash('用户名或密码错误。')
    return render_template('user/login.html')


@app.route('/user/logout')
def user_logout():
    session.clear()
    flash('已退出登录。')
    return redirect(url_for('index'))


@app.route('/user/change-password', methods=['GET', 'POST'])
@login_required
@csrf_required
def change_password():
    if request.method == 'POST':
        old_pw = request.form.get('old_password', '')
        new_pw = request.form.get('new_password', '')
        new_pw2 = request.form.get('new_password2', '')
        user = models.get_user_by_username(session['username'])
        if not user or not check_password_hash(user['password_hash'], old_pw):
            flash('旧密码错误。')
        elif len(new_pw) < 6:
            flash('新密码至少6位。')
        elif new_pw != new_pw2:
            flash('两次新密码不一致。')
        else:
            models.change_password(session['user_id'], generate_password_hash(new_pw))
            flash('密码修改成功！')
            return redirect(url_for('index'))
    return render_template('user/change-password.html')


@app.route('/user/avatar', methods=['GET', 'POST'])
@login_required
@csrf_required
def user_avatar():
    user = models.get_user_by_id(session['user_id'])
    if request.method == 'POST':
        f = request.files.get('avatar')
        if not f or not f.filename:
            flash('请选择图片文件。')
        elif not allowed_file(f.filename):
            flash('不支持的图片格式，仅支持 png/jpg/jpeg/gif/webp/bmp。')
        elif not validate_image_content(f)[0]:
            flash('文件内容不是有效的图片。')
        else:
            ext = f.filename.rsplit('.', 1)[1].lower()
            filename = f'{uuid.uuid4().hex}.{ext}'
            filepath = os.path.join(AVATAR_DIR, filename)
            f.save(filepath)
            # Remove old avatar
            if user.get('avatar'):
                old_path = os.path.join(os.path.dirname(__file__), user['avatar'].lstrip('/'))
                if os.path.exists(old_path):
                    os.remove(old_path)
            avatar_url = f'/static/avatars/{filename}'
            models.update_avatar(session['user_id'], avatar_url)
            session['avatar'] = avatar_url
            flash('头像已更新！')
            return redirect(url_for('index'))
    return render_template('user/avatar.html', user=user)


# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=10, window=60)
@csrf_required
def admin_login():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = models.get_user_by_username(username)
        if user and user['role'] == 'admin' and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['avatar'] = user.get('avatar', '')
            return redirect(url_for('admin_dashboard'))
        flash('管理员用户名或密码错误。')
    return render_template('admin/login.html')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    articles, total = models.get_articles(page, PER_PAGE)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render_template('admin/dashboard.html', articles=articles,
                           page=page, total_pages=total_pages)


def _get_server_stats():
    """Collect server resource usage. Returns dict for JSON response."""
    stats = {}
    try:
        # --- CPU usage (2 samples with 0.3s gap) ---
        def _read_cpu():
            with open('/proc/stat') as f:
                for line in f:
                    if line.startswith('cpu '):
                        parts = line.split()
                        return sum(int(x) for x in parts[1:]), int(parts[4])
        if os.path.exists('/proc/stat'):
            t1, i1 = _read_cpu()
            _time.sleep(0.3)
            t2, i2 = _read_cpu()
            total_delta = t2 - t1
            idle_delta = i2 - i1
            stats['cpu_percent'] = round((1 - idle_delta / total_delta) * 100, 1) if total_delta > 0 else 0
        else:
            stats['cpu_percent'] = None

        # --- Memory ---
        if os.path.exists('/proc/meminfo'):
            mem = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    if line.startswith(('MemTotal', 'MemAvailable', 'MemFree', 'Buffers', 'Cached')):
                        k, v = line.split(':')
                        mem[k.strip()] = int(v.strip().split()[0])
            stats['mem_total'] = mem.get('MemTotal', 0) // 1024  # MB
            stats['mem_available'] = mem.get('MemAvailable', 0) // 1024
            stats['mem_used'] = stats['mem_total'] - stats['mem_available']

        # --- Disk ---
        st = os.statvfs('/')
        stats['disk_total'] = round(st.f_frsize * st.f_blocks / (1024 ** 3), 1)  # GB
        stats['disk_used'] = round(st.f_frsize * (st.f_blocks - st.f_bfree) / (1024 ** 3), 1)
        stats['disk_free'] = round(st.f_frsize * st.f_bavail / (1024 ** 3), 1)

        # --- Uptime ---
        if os.path.exists('/proc/uptime'):
            with open('/proc/uptime') as f:
                stats['uptime_seconds'] = int(float(f.read().split()[0]))

        # --- Load Average + CPU cores ---
        if os.path.exists('/proc/loadavg'):
            with open('/proc/loadavg') as f:
                parts = f.read().split()
                stats['load_1'] = float(parts[0])
                stats['load_5'] = float(parts[1])
                stats['load_15'] = float(parts[2])
        stats['cpu_cores'] = os.cpu_count() or 1

        # --- Network I/O ---
        if os.path.exists('/proc/net/dev'):
            with open('/proc/net/dev') as f:
                rx = tx = 0
                for line in f:
                    if ':' in line and 'lo:' not in line:
                        parts = line.split(':')[1].split()
                        rx += int(parts[0])
                        tx += int(parts[8])
                stats['net_rx_mb'] = round(rx / (1024 ** 2), 1)
                stats['net_tx_mb'] = round(tx / (1024 ** 2), 1)
    except Exception as e:
        stats['error'] = str(e)
    return stats


@app.route('/admin/monitor')
@admin_required
def admin_monitor():
    return render_template('admin/monitor.html')


@app.route('/admin/monitor/api')
@admin_required
def admin_monitor_api():
    return jsonify(_get_server_stats())


@app.route('/admin/upload', methods=['POST'])
@admin_required
@csrf_required
def admin_upload():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': '未选择文件'}), 400
    if not allowed_file(f.filename):
        return jsonify({'ok': False, 'error': '不支持的图片格式'}), 400
    valid_mime, _ = validate_image_content(f)
    if not valid_mime:
        return jsonify({'ok': False, 'error': '文件内容不是有效的图片'}), 400
    ext = f.filename.rsplit('.', 1)[1].lower()
    orig_name = f.filename.rsplit('.', 1)[0]
    safe_base = re.sub(r'[\\/:*?"<>|]', '_', orig_name).strip()
    if not safe_base:
        safe_base = 'image'
    filename = f'{safe_base}.{ext}'
    filepath = os.path.join(UPLOAD_DIR, filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f'{safe_base} ({counter}).{ext}'
        filepath = os.path.join(UPLOAD_DIR, filename)
        counter += 1
    f.save(filepath)
    # Generate thumbnail
    try:
        img = Image.open(filepath)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGBA')
        else:
            img = img.convert('RGB')
        w, h = img.size
        thumb_w = 360
        thumb = img.copy()
        if w > thumb_w:
            thumb = thumb.resize((thumb_w, int(h * thumb_w / w)), Image.LANCZOS)
        thumb_ext = 'png' if ext == 'png' and img.mode == 'RGBA' else 'jpg'
        thumb_filename = f'{filename.rsplit(".", 1)[0]}.{thumb_ext}'
        thumb_path = os.path.join(THUMB_DIR, thumb_filename)
        if thumb.mode == 'RGBA':
            thumb.save(thumb_path, optimize=True)
        else:
            thumb.save(thumb_path, quality=60, optimize=True)
    except Exception as e:
        import traceback
        traceback.print_exc()
    url = f'/static/uploads/{filename}'
    return jsonify({'ok': True, 'url': url})


@app.route('/admin/upload-video', methods=['POST'])
@admin_required
@csrf_required
def admin_upload_video():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': '未选择文件'}), 400
    if not is_video_file(f.filename):
        return jsonify({'ok': False, 'error': '不支持的视频格式，仅支持 mp4/webm/mov'}), 400
    ext = f.filename.rsplit('.', 1)[1].lower() if '.' in f.filename else ''
    orig_name = f.filename.rsplit('.', 1)[0] if '.' in f.filename else f.filename
    safe_base = re.sub(r'[\\/:*?"<>|]', '_', orig_name).strip()
    if not safe_base:
        safe_base = 'video'
    filename = f'{safe_base}.{ext}' if ext else safe_base
    filepath = os.path.join(UPLOAD_DIR, filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f'{safe_base} ({counter}).{ext}' if ext else f'{safe_base} ({counter})'
        filepath = os.path.join(UPLOAD_DIR, filename)
        counter += 1
    f.save(filepath)
    base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
    generate_video_thumbnail(filepath, THUMB_DIR, base_name)
    url = f'/static/uploads/{filename}'
    return jsonify({'ok': True, 'url': url})


@app.route('/admin/upload-attachment', methods=['POST'])
@admin_required
@csrf_required
def admin_upload_attachment():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': '未选择文件'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext in ATTACH_BLOCKED:
        return jsonify({'ok': False, 'error': '不支持的文件类型'}), 400
    # Sanitize: keep original name, prevent path traversal
    orig_name = f.filename.rsplit('.', 1)[0] if '.' in f.filename else f.filename
    safe_base = re.sub(r'[\\/:*?"<>|]', '_', orig_name).strip()
    if not safe_base:
        safe_base = 'file'
    safe_name = f'{safe_base}.{ext}' if ext else safe_base
    # Avoid overwrite: append (1), (2), etc.
    filepath = os.path.join(ATTACH_DIR, safe_name)
    counter = 1
    while os.path.exists(filepath):
        if ext:
            safe_name = f'{safe_base} ({counter}).{ext}'
        else:
            safe_name = f'{safe_base} ({counter})'
        filepath = os.path.join(ATTACH_DIR, safe_name)
        counter += 1
    f.save(filepath)
    size = os.path.getsize(filepath)
    url = f'/static/uploads/attachments/{safe_name}'
    return jsonify({'ok': True, 'url': url, 'filename': safe_name, 'size': size})


@app.route('/admin/article/new', methods=['GET', 'POST'])
@admin_required
@csrf_required
def admin_new_article():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        summary = request.form.get('summary', '').strip()
        created_at = request.form.get('created_at', '').strip().replace('T', ' ')
        custom_id = request.form.get('article_id', '').strip()
        if title:
            aid = None
            if custom_id:
                try:
                    aid = int(custom_id)
                    if aid < 1:
                        flash('文章ID必须为正整数。')
                        return render_template('admin/edit.html', article=None)
                    if models.get_article(aid):
                        flash(f'ID {aid} 已被占用，请换一个。')
                        return render_template('admin/edit.html', article=None)
                except ValueError:
                    flash('文章ID必须为整数。')
                    return render_template('admin/edit.html', article=None)
            models.create_article(title, content, summary, created_at or None, aid)
            flash('文章已发布！')
            return redirect(url_for('admin_dashboard'))
        flash('标题不能为空。')
    return render_template('admin/edit.html', article=None)


@app.route('/admin/article/<int:article_id>/edit', methods=['GET', 'POST'])
@admin_required
@csrf_required
def admin_edit_article(article_id):
    article = models.get_article(article_id)
    if not article:
        return render_template('404.html'), 404
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        summary = request.form.get('summary', '').strip()
        created_at = request.form.get('created_at', '').strip().replace('T', ' ')
        custom_id = request.form.get('article_id', '').strip()
        new_id = None
        if custom_id:
            try:
                new_id = int(custom_id)
                if new_id < 1:
                    flash('文章ID必须为正整数。')
                    return render_template('admin/edit.html', article=article)
                if new_id != article_id:
                    existing = models.get_article(new_id)
                    if existing:
                        flash(f'ID {new_id} 已被占用，请换一个。')
                        return render_template('admin/edit.html', article=article)
            except ValueError:
                flash('文章ID必须为整数。')
                return render_template('admin/edit.html', article=article)
        if title:
            models.update_article(article_id, title, content, summary, created_at or None, new_id)
            flash('文章已更新！')
            if new_id and new_id != article_id:
                return redirect(url_for('admin_edit_article', article_id=new_id))
            return redirect(url_for('admin_dashboard'))
        flash('标题不能为空。')
    return render_template('admin/edit.html', article=article)


@app.route('/admin/article/<int:article_id>/pin', methods=['POST'])
@admin_required
@csrf_required
def admin_pin_article(article_id):
    models.toggle_pin(article_id)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/article/<int:article_id>/hide', methods=['POST'])
@admin_required
@csrf_required
def admin_hide_article(article_id):
    models.toggle_hidden(article_id)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/article/<int:article_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_article(article_id):
    article = models.get_article(article_id)
    if article:
        # Delete images/videos referenced only by this article
        img_urls = IMG_RE.findall(article.get('content', ''))
        video_urls = VIDEO_RE.findall(article.get('content', ''))
        all_urls = img_urls + video_urls
        models.delete_article(article_id)
        for url in all_urls:
            if url.startswith('/static/uploads/') and not models.is_image_used(url):
                fpath = os.path.join(os.path.dirname(__file__), url.lstrip('/'))
                if os.path.exists(fpath):
                    os.remove(fpath)
                fname = url.rsplit('/', 1)[-1]
                if not is_video_file(fname):
                    base = fname.rsplit('.', 1)[0]
                    for ext in ('jpg', 'png', 'webp', 'gif'):
                        tp = os.path.join(THUMB_DIR, f'{base}.{ext}')
                        if os.path.exists(tp):
                            os.remove(tp)
    flash('文章已删除。')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = models.get_all_users()
    return render_template('admin/users.html', users=users)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        flash('不能删除自己。')
    else:
        models.delete_user(user_id)
        flash('用户已删除。')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/new', methods=['POST'])
@admin_required
@csrf_required
def admin_create_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user').strip()
    user_id_str = request.form.get('user_id', '').strip()
    user_id = int(user_id_str) if user_id_str else None
    if not username or not password:
        flash('请填写用户名和密码。')
    elif len(username) < 2 or len(username) > 30:
        flash('用户名需要2-30个字符。')
    elif len(password) < 6:
        flash('密码至少6位。')
    elif role not in ('user', 'admin'):
        flash('无效的角色。')
    elif models.get_user_by_username(username):
        flash('该用户名已存在。')
    elif user_id is not None and models.get_user_by_id(user_id):
        flash(f'用户ID {user_id} 已被占用。')
    else:
        pw_hash = generate_password_hash(password)
        result = models.create_user(username, pw_hash, role=role, user_id=user_id)
        if result:
            flash(f'用户 {username} 已创建（ID: {result}）。')
        else:
            flash('创建失败，ID可能已被占用。')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@admin_required
@csrf_required
def admin_edit_user(user_id):
    user = models.get_user_by_id(user_id)
    if not user:
        flash('用户不存在。')
        return redirect(url_for('admin_users'))
    username = request.form.get('username', '').strip()
    role = request.form.get('role', '').strip()
    if username and username != user['username']:
        if models.get_user_by_username(username):
            flash('该用户名已被占用。')
            return redirect(url_for('admin_users'))
        models.update_user(user_id, username=username)
        if user_id == session['user_id']:
            session['username'] = username
    if role in ('user', 'admin') and role != user['role']:
        models.update_user(user_id, role=role)
        if user_id == session['user_id']:
            session['role'] = role
    # Change user ID
    new_id_str = request.form.get('new_user_id', '').strip()
    new_user_id = int(new_id_str) if new_id_str else None
    if new_user_id is not None and new_user_id != user_id:
        existing = models.get_user_by_id(new_user_id)
        if existing:
            flash(f'ID {new_user_id} 已被占用。')
            return redirect(url_for('admin_users'))
        models.update_user(user_id, new_user_id=new_user_id)
        if user_id == session['user_id']:
            session['user_id'] = new_user_id
        user_id = new_user_id
    # Avatar upload
    f = request.files.get('avatar')
    if f and f.filename and allowed_file(f.filename) and validate_image_content(f)[0]:
        ext = f.filename.rsplit('.', 1)[1].lower()
        filename = f'{uuid.uuid4().hex}.{ext}'
        filepath = os.path.join(AVATAR_DIR, filename)
        f.save(filepath)
        if user.get('avatar'):
            old_path = os.path.join(os.path.dirname(__file__), user['avatar'].lstrip('/'))
            if os.path.exists(old_path):
                os.remove(old_path)
        avatar_url = f'/static/avatars/{filename}'
        models.update_user(user_id, avatar=avatar_url)
        if user_id == session['user_id']:
            session['avatar'] = avatar_url
    flash(f'用户 {username or user["username"]} 已更新。')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/password', methods=['GET', 'POST'])
@admin_required
@csrf_required
def admin_change_user_password(user_id):
    user = models.get_user_by_id(user_id)
    if not user:
        flash('用户不存在。')
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        new_pw2 = request.form.get('new_password2', '')
        if len(new_pw) < 6:
            flash('密码至少6位。')
        elif new_pw != new_pw2:
            flash('两次密码不一致。')
        else:
            models.change_password(user_id, generate_password_hash(new_pw))
            flash(f'用户 {user["username"]} 的密码已修改。')
            return redirect(url_for('admin_users'))
    return render_template('admin/user_password.html', user=user)


@app.route('/admin/comments')
@admin_required
def admin_comments():
    comments = models.get_all_comments()
    return render_template('admin/comments.html', comments=comments)


@app.route('/admin/comment/<int:comment_id>/delete', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_comment(comment_id):
    models.delete_comment(comment_id)
    flash('评论已删除。')
    return redirect(url_for('admin_comments'))


def format_size(bytesize):
    if bytesize >= 1048576:
        return f'{bytesize / 1048576:.1f} MB'
    if bytesize >= 1024:
        return f'{bytesize / 1024:.1f} KB'
    return f'{bytesize} B'


@app.route('/admin/images')
@admin_required
def admin_images():
    images = []
    for fname in sorted(os.listdir(UPLOAD_DIR), reverse=True):
        if not allowed_media_file(fname):
            continue
        fpath = os.path.join(UPLOAD_DIR, fname)
        url = f'/static/uploads/{fname}'
        fsize = format_size(os.path.getsize(fpath))
        is_video = is_video_file(fname)
        base = fname.rsplit('.', 1)[0]
        thumb_url = url
        for try_ext in ('jpg', 'png', 'webp'):
            tp = os.path.join(THUMB_DIR, f'{base}.{try_ext}')
            if os.path.exists(tp):
                thumb_url = f'/static/uploads/thumbs/{base}.{try_ext}'
                break
        articles = models.get_image_articles(url)
        images.append({'filename': fname, 'url': url, 'thumb_url': thumb_url,
                       'size': fsize, 'used': len(articles) > 0,
                       'articles': articles, 'is_video': is_video})
    return render_template('admin/images.html', images=images)


@app.route('/admin/images/list')
@admin_required
def admin_images_list():
    imgs = []
    for fname in sorted(os.listdir(UPLOAD_DIR), reverse=True):
        if not allowed_media_file(fname):
            continue
        is_video = is_video_file(fname)
        base = fname.rsplit('.', 1)[0]
        thumb_url = f'/static/uploads/{fname}'
        if is_video:
            for try_ext in ('jpg', 'png'):
                tp = os.path.join(THUMB_DIR, f'{base}.{try_ext}')
                if os.path.exists(tp):
                    thumb_url = f'/static/uploads/thumbs/{base}.{try_ext}'
                    break
        imgs.append({'url': f'/static/uploads/{fname}', 'name': fname,
                     'thumb_url': thumb_url, 'is_video': is_video})
    return jsonify(imgs)


@app.route('/admin/image/<fname>/rename', methods=['POST'])
@admin_required
@csrf_required
def admin_rename_image(fname):
    fname = safe_filename(fname, UPLOAD_DIR)
    if not fname:
        return jsonify(ok=False, error='非法的文件名。')
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        return jsonify(ok=False, error='请输入新文件名。')
    # Must keep same extension
    old_ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
    new_ext = new_name.rsplit('.', 1)[-1].lower() if '.' in new_name else ''
    if old_ext and new_ext != old_ext:
        return jsonify(ok=False, error=f'扩展名不一致，请保持 .{old_ext}')
    if not allowed_media_file(new_name):
        return jsonify(ok=False, error='非法的文件扩展名。')
    valid = safe_filename(new_name, UPLOAD_DIR)
    if not valid:
        return jsonify(ok=False, error='文件名包含非法字符。')
    old_path = os.path.join(UPLOAD_DIR, fname)
    new_path = os.path.join(UPLOAD_DIR, valid)
    if not os.path.exists(old_path):
        return jsonify(ok=False, error='原文件不存在。')
    if os.path.exists(new_path):
        return jsonify(ok=False, error='该文件名已存在。')
    os.rename(old_path, new_path)
    # Rename matching thumbnail
    old_base = fname.rsplit('.', 1)[0]
    new_base = valid.rsplit('.', 1)[0]
    for ext in ('jpg', 'png', 'webp', 'gif'):
        old_thumb = os.path.join(THUMB_DIR, f'{old_base}.{ext}')
        if os.path.exists(old_thumb):
            new_thumb = os.path.join(THUMB_DIR, f'{new_base}.{ext}')
            os.rename(old_thumb, new_thumb)
    # Update article references
    old_url = f'/static/uploads/{fname}'
    new_url = f'/static/uploads/{valid}'
    models.rename_file_references(old_url, new_url)
    # Also update old thumb URL references if thumb extension changed
    for ext in ('jpg', 'png', 'webp', 'gif'):
        old_thumb_url = f'/static/uploads/thumbs/{old_base}.{ext}'
        new_thumb_url = f'/static/uploads/thumbs/{new_base}.{ext}'
        if old_thumb_url != new_thumb_url:
            models.rename_file_references(old_thumb_url, new_thumb_url)
    return jsonify(ok=True, new_name=valid)


@app.route('/admin/attachment/<fname>/rename', methods=['POST'])
@admin_required
@csrf_required
def admin_rename_attachment(fname):
    fname = safe_filename(fname, ATTACH_DIR)
    if not fname:
        return jsonify(ok=False, error='非法的文件名。')
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        return jsonify(ok=False, error='请输入新文件名。')
    # Must keep same extension for attachments too
    old_ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
    new_ext = new_name.rsplit('.', 1)[-1].lower() if '.' in new_name else ''
    if old_ext and new_ext != old_ext:
        return jsonify(ok=False, error=f'扩展名不一致，请保持 .{old_ext}')
    valid = safe_filename(new_name, ATTACH_DIR)
    if not valid:
        return jsonify(ok=False, error='文件名包含非法字符。')
    old_path = os.path.join(ATTACH_DIR, fname)
    new_path = os.path.join(ATTACH_DIR, valid)
    if not os.path.exists(old_path):
        return jsonify(ok=False, error='原文件不存在。')
    if os.path.exists(new_path):
        return jsonify(ok=False, error='该文件名已存在。')
    os.rename(old_path, new_path)
    old_url = f'/static/uploads/attachments/{fname}'
    new_url = f'/static/uploads/attachments/{valid}'
    models.rename_file_references(old_url, new_url)
    return jsonify(ok=True, new_name=valid)


@app.route('/admin/image/<fname>/delete', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_image(fname):
    fname = safe_filename(fname, UPLOAD_DIR)
    if not fname:
        flash('非法的文件名。')
        return redirect(url_for('admin_images'))
    url = f'/static/uploads/{fname}'
    if models.is_image_used(url):
        flash('该文件仍被文章引用，无法删除。')
    else:
        fpath = os.path.join(UPLOAD_DIR, fname)
        if os.path.exists(fpath):
            os.remove(fpath)
        base = fname.rsplit('.', 1)[0]
        for ext in ('jpg', 'png', 'webp', 'gif'):
            tp = os.path.join(THUMB_DIR, f'{base}.{ext}')
            if os.path.exists(tp):
                os.remove(tp)
        flash('文件已删除。')
    return redirect(url_for('admin_images'))


@app.route('/admin/attachments')
@admin_required
def admin_attachments():
    attachments = []
    for fname in sorted(os.listdir(ATTACH_DIR), reverse=True):
        fpath = os.path.join(ATTACH_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        url = f'/static/uploads/attachments/{fname}'
        fsize = format_size(os.path.getsize(fpath))
        articles = models.get_image_articles(url)
        attachments.append({'filename': fname, 'url': url, 'size': fsize,
                          'used': len(articles) > 0, 'articles': articles})
    return render_template('admin/attachments.html', attachments=attachments)


@app.route('/admin/attachments/list')
@admin_required
def admin_attachments_list():
    items = []
    for fname in sorted(os.listdir(ATTACH_DIR), reverse=True):
        if not os.path.isfile(os.path.join(ATTACH_DIR, fname)):
            continue
        items.append({'url': f'/static/uploads/attachments/{fname}', 'name': fname})
    return jsonify(items)


@app.route('/admin/attachment/<fname>/delete', methods=['POST'])
@admin_required
@csrf_required
def admin_delete_attachment(fname):
    fname = safe_filename(fname, ATTACH_DIR)
    if not fname:
        flash('非法的文件名。')
        return redirect(url_for('admin_attachments'))
    url = f'/static/uploads/attachments/{fname}'
    if models.is_image_used(url):
        flash('该附件仍被文章引用，无法删除。')
    else:
        fpath = os.path.join(ATTACH_DIR, fname)
        if os.path.exists(fpath):
            os.remove(fpath)
        flash('附件已删除。')
    return redirect(url_for('admin_attachments'))


@app.route('/admin/background', methods=['GET', 'POST'])
@admin_required
@csrf_required
def admin_background():
    if request.method == 'POST':
        if 'remove' in request.form:
            cfg = get_config()
            old = cfg.pop('bg_image', '')
            cfg['bg_blur'] = 18
            save_config(cfg)
            if old:
                old_path = os.path.join(os.path.dirname(__file__), old.lstrip('/'))
                if os.path.exists(old_path):
                    os.remove(old_path)
            flash('背景图已移除，模糊参数已恢复默认。')
            return redirect(url_for('admin_background'))
        if 'save_blur' in request.form:
            cfg = get_config()
            try:
                cfg['bg_blur'] = max(1, min(40, int(request.form.get('blur', 18))))
            except (ValueError, TypeError):
                cfg['bg_blur'] = 18
            save_config(cfg)
            flash(f'模糊参数已更新为 {cfg["bg_blur"]}px。')
            return redirect(url_for('admin_background'))
        f = request.files.get('bg')
        if not f or not f.filename:
            flash('请选择图片文件。')
        elif not allowed_file(f.filename):
            flash('不支持的图片格式。')
        elif not validate_image_content(f)[0]:
            flash('文件内容不是有效的图片。')
        else:
            filename = f'bg_{uuid.uuid4().hex[:8]}.webp'
            filepath = os.path.join(BG_DIR, filename)
            img = Image.open(f)
            img = img.convert('RGB')
            w, h = img.size
            # 背景会被模糊，不需要高分辨率，800px 足够
            max_w, max_h = 800, 600
            if w > max_w or h > max_h:
                ratio = min(max_w / w, max_h / h)
                img = img.resize((int(w * ratio), int(h * ratio)), Image.LANCZOS)
            img.save(filepath, format='WEBP', quality=50)
            cfg = get_config()
            old = cfg.get('bg_image', '')
            cfg['bg_image'] = f'/static/bg/{filename}'
            save_config(cfg)
            if old:
                old_path = os.path.join(os.path.dirname(__file__), old.lstrip('/'))
                if os.path.exists(old_path):
                    os.remove(old_path)
            flash('背景图已更新！')
            return redirect(url_for('admin_background'))
    cfg = get_config()
    return render_template('admin/background.html',
                           bg_image=cfg.get('bg_image', ''),
                           bg_blur=cfg.get('bg_blur', 18))


@app.route('/admin/profile', methods=['GET', 'POST'])
@admin_required
@csrf_required
def admin_profile():
    if request.method == 'POST':
        cfg = get_config()
        cfg['profile_title'] = request.form.get('title', '').strip()
        cfg['profile_content'] = request.form.get('content', '').strip()
        cfg['site_title'] = request.form.get('site_title', '').strip()
        cfg['site_subtitle'] = request.form.get('site_subtitle', '').strip()
        save_config(cfg)
        flash('个人简介已更新。')
        return redirect(url_for('admin_profile'))
    cfg = get_config()
    return render_template('admin/profile.html',
                           title=cfg.get('profile_title', ''),
                           content=cfg.get('profile_content', ''),
                           site_title=cfg.get('site_title', '繁星绘流萤'),
                           site_subtitle=cfg.get('site_subtitle', '记录思考，分享生活'))


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
