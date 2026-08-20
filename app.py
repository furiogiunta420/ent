from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, send_from_directory
from datetime import datetime, timedelta
import hashlib
import json
import os
import re
import secrets
import shutil
import uuid
from dotenv import load_dotenv, set_key
from werkzeug.utils import secure_filename
import sys 
import time
from flask_session import Session 

load_dotenv()





app = Flask(__name__, static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))

app.secret_key = os.getenv("SECRET_KEY", "change-me-flask-secret") 

# Server-side sessions — cookie holds only a random ID
app.config["SESSION_TYPE"]               = "filesystem"
app.config["SESSION_FILE_DIR"]           = ".flask_sessions"
app.config["SESSION_FILE_THRESHOLD"]     = 500
app.config["SESSION_PERMANENT"]          = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"]    = True
app.config["SESSION_COOKIE_SAMESITE"]    = "Lax"


Session(app)

DATA_FILE     = "messages.dat"      
UPLOAD_FOLDER = "uploads"           
KEY_BUNDLE_DIR = "keybundles"       
ENV_FILE      = ".env"
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "pdf", "txt", "zip",
    "mp4", "mov",
    "mp3", "wav", "m4a", "ogg", "flac", "aac",
}
MAX_FILE_MB   = 16

app.config["UPLOAD_FOLDER"]      = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024


JSON_ENVELOPE_RESERVE_BYTES = 2048
CRYPTO_OVERHEAD_BYTES       = 28  # 12-byte IV + 16-byte GCM tag

def max_original_upload_bytes() -> int:
    encoded_budget = app.config["MAX_CONTENT_LENGTH"] - JSON_ENVELOPE_RESERVE_BYTES
    raw_before_b64 = (encoded_budget * 3) // 4
    return max(raw_before_b64 - CRYPTO_OVERHEAD_BYTES, 0)

os.makedirs(UPLOAD_FOLDER,     exist_ok=True)
os.makedirs(".flask_sessions", exist_ok=True)
os.makedirs(KEY_BUNDLE_DIR,    exist_ok=True)


# ─── Message store ────────────────────────────────────────────────────────────
# Messages are stored as-received ciphertext. The server cannot read them.

def load_messages() -> list:
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r") as fh:
            return json.load(fh)
    except Exception:
        return []

def save_messages(messages: list) -> None:
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(messages, fh)
    os.replace(tmp, DATA_FILE)

def nuke_all() -> None:
    """Wipe all messages, uploaded files, and key bundles."""
    for folder in [UPLOAD_FOLDER]: #,KEY_BUNDLE_DIR
        if os.path.exists(folder):
            for fname in os.listdir(folder):
                try:
                    os.remove(os.path.join(folder, fname))
                except OSError:
                    pass
    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)


# ─── User / auth helpers ──────────────────────────────────────────────────────
# Users are stored as username:auth_token_hash pairs.
# auth_token_hash = SHA-256(client-derived PBKDF2 token).


def get_users() -> dict:
    users = {}
    for entry in os.getenv("USERS", "").split(","):
        entry = entry.strip()
        if ":" in entry:
            u, p = entry.split(":", 1)
            users[u.strip()] = p.strip()
    return users

def write_users(users: dict) -> None:
    value = ",".join(f"{u}:{p}" for u, p in users.items())
    set_key(ENV_FILE, "USERS", value)
    os.environ["USERS"] = value

def check_auth_token(stored_hash: str, submitted_token: str) -> bool:
    """
    Stored value is SHA-256(auth_token). Client submits the raw auth_token.
    We hash what the client sent and compare — never store raw token.
    """
    submitted_hash = hashlib.sha256(submitted_token.encode()).hexdigest()
    return secrets.compare_digest(stored_hash, submitted_hash)

def hash_auth_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()

def valid_username(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]{1,32}$', name))

def get_admin() -> str:
    return os.getenv("ADMIN_USER", "").strip()

def set_admin(username: str) -> None:
    set_key(ENV_FILE, "ADMIN_USER", username)
    os.environ["ADMIN_USER"] = username

def get_nuke_command() -> str:
    return os.getenv("NUKE_COMMAND", "/NUKE").strip()

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def mime_for(ext: str) -> str:
    return {
        "png": "image/png",   "jpg": "image/jpeg",  "jpeg": "image/jpeg",
        "gif": "image/gif",   "webp": "image/webp",  "pdf": "application/pdf",
        "txt": "text/plain",  "zip": "application/zip",
        "mp4": "video/mp4",   "mov": "video/quicktime",
        "mp3": "audio/mpeg",  "wav": "audio/wav",    "m4a": "audio/mp4",
        "ogg": "audio/ogg",   "flac": "audio/flac",  "aac": "audio/aac",
    }.get(ext.lower(), "application/octet-stream")

def require_admin():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if session["username"] != get_admin():
        return jsonify({"error": "Forbidden"}), 403
    return None


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    max_bytes = max_original_upload_bytes()
    return render_template("chat.html",
                           username=session["username"],
                           is_admin=session["username"] == get_admin(),
                           nuke_cmd=get_nuke_command(),
                           max_upload_bytes=max_bytes,
                           max_upload_label=f"{max_bytes / (1024 * 1024):.1f} MB")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data     = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        token    = data.get("auth_token", "").strip()   # PBKDF2-derived, never the password

        if not username or not token:
            return jsonify({"error": "Missing credentials"}), 400

        users = get_users()
        if username not in users:
            return jsonify({"error": "Invalid username or password"}), 401

        stored = users[username]

        # Support legacy bcrypt hashes during migration period
        if stored.startswith("$2b$") or stored.startswith("$2a$"):
            return jsonify({"error": "Account needs migration. Contact admin."}), 401

        if not check_auth_token(stored, token):
            return jsonify({"error": "Invalid username or password"}), 401

        session["username"] = username
        return jsonify({"ok": True, "is_admin": username == get_admin()})

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/whoami")
def whoami():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    users        = get_users()
    is_first     = len(users) == 1 and session["username"] in users
    return jsonify({
        "username":     session["username"],
        "is_admin":     session["username"] == get_admin(),
        "is_first_user": is_first,
    })


# ─── Group key routes ─────────────────────────────────────────────────────────


@app.route("/groupkey", methods=["GET", "POST"])
def groupkey_self():
    """Get or set the calling user's wrapped group key bundle."""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    bundle_path = os.path.join(KEY_BUNDLE_DIR, f"{session['username']}.bundle")

    if request.method == "POST":
        data   = request.get_json()
        bundle = (data.get("bundle") or "").strip()
        if not bundle:
            return jsonify({"error": "Empty bundle"}), 400
        with open(bundle_path, "w") as fh:
            fh.write(bundle)
        return jsonify({"ok": True})

    if not os.path.exists(bundle_path):
        return jsonify({"bundle": None})
    with open(bundle_path) as fh:
        return jsonify({"bundle": fh.read().strip()})


@app.route("/groupkey/<target_username>", methods=["GET", "POST"])
def groupkey_for_user(target_username):
    """
    GET  — any logged-in user can fetch another user's wrapped bundle
           (needed so a new user can receive the group key from an existing one)
    POST — admin-only: store a wrapped group key for another user
           (used when admin adds a new user and pushes the group key to them)
    """
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    target_username = os.path.basename(target_username)
    bundle_path     = os.path.join(KEY_BUNDLE_DIR, f"{target_username}.bundle")

    if request.method == "POST":
        if session["username"] != get_admin():
            return jsonify({"error": "Forbidden"}), 403
        data   = request.get_json()
        bundle = (data.get("bundle") or "").strip()
        if not bundle:
            return jsonify({"error": "Empty bundle"}), 400
        with open(bundle_path, "w") as fh:
            fh.write(bundle)
        return jsonify({"ok": True})

    if not os.path.exists(bundle_path):
        return jsonify({"bundle": None})
    with open(bundle_path) as fh:
        return jsonify({"bundle": fh.read().strip()})


@app.route("/groupkey/raw", methods=["GET"])
def groupkey_raw_export():
    """
    Returns the calling user's own wrapped bundle — used by the admin's
    browser to read the group key so it can re-wrap it for a new user.
    Only the admin calls this; regular users get their bundle from /groupkey.
    """
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if session["username"] != get_admin():
        return jsonify({"error": "Forbidden"}), 403

    bundle_path = os.path.join(KEY_BUNDLE_DIR, f"{session['username']}.bundle")
    if not os.path.exists(bundle_path):
        return jsonify({"bundle": None})
    with open(bundle_path) as fh:
        return jsonify({"bundle": fh.read().strip()})


# ─── Message routes ───────────────────────────────────────────────────────────

@app.route("/messages")
def get_messages():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(load_messages())

@app.route("/send", methods=["POST"])
def send_message():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    # NUKE — sent as plaintext flag, not encrypted
    if data.get("nuke"):
        if session["username"] != get_admin():
            return jsonify({"error": "Forbidden"}), 403
        nuke_all()
        return jsonify({"nuked": True})

    # Encrypted message blob from client
    ciphertext = data.get("ciphertext", "").strip()
    if not ciphertext:
        return jsonify({"error": "Empty message"}), 400

    messages  = load_messages()
    msg_id    = (messages[-1]["id"] + 1) if messages else 1
    timestamp = datetime.now().strftime("%b %d, %Y %I:%M %p")

    msg = {
        "id":        msg_id,
        "username": session["username"],
        "ciphertext": ciphertext,       # server only ever sees this
        "file_name": None,
        "file_orig": None,
        "file_mime": None,
        "timestamp": timestamp,
    }
    messages.append(msg)
    save_messages(messages)
    return jsonify(msg)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # File arrives as encrypted base64 blob in JSON, not as multipart
    data      = request.get_json()
    enc_b64   = data.get("ciphertext", "").strip()
    orig_name = data.get("original_name", "file").strip()
    mime_type = data.get("mime_type", "application/octet-stream").strip()

    if not enc_b64:
        return jsonify({"error": "No file data"}), 400

    ext        = secure_filename(orig_name).rsplit(".", 1)[-1].lower() if "." in orig_name else "bin"
    saved_name = f"{uuid.uuid4().hex}.{ext}"

    # Write the encrypted blob directly — server never sees plaintext bytes
    with open(os.path.join(UPLOAD_FOLDER, saved_name), "w") as fh:
        fh.write(enc_b64)

    messages  = load_messages()
    msg_id    = (messages[-1]["id"] + 1) if messages else 1
    timestamp = datetime.now().strftime("%b %d, %Y %I:%M %p")

    msg = {
        "id":         msg_id,
        "username":   session["username"],
        "ciphertext": None,
        "file_name":  saved_name,
        "file_orig":  orig_name,
        "file_mime":  mime_type,
        "timestamp":  timestamp,
    }
    messages.append(msg)
    save_messages(messages)
    return jsonify(msg)

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """Returns the raw encrypted blob. Client decrypts it."""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    filename = os.path.basename(filename)
    fpath    = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(fpath):
        return "Not found", 404
    with open(fpath, "r") as fh:
        return jsonify({"ciphertext": fh.read().strip()})


# ─── Admin routes ─────────────────────────────────────────────────────────────

@app.route("/admin")
def admin():
    if "username" not in session:
        return redirect(url_for("login"))
    if session["username"] != get_admin():
        return redirect(url_for("index"))
    users    = get_users()
    admin_un = get_admin()
    user_list = [
        {"username": u, "is_admin": u == admin_un}
        for u in users
    ]
    return render_template("admin.html",
                           username=session["username"],
                           users=user_list,
                           admin_username=admin_un,
                           nuke_cmd=get_nuke_command())

@app.route("/admin/add-user", methods=["POST"])
def admin_add_user():
    err = require_admin()
    if err: return err

    data       = request.get_json()
    new_user   = (data.get("username") or "").strip()
    auth_token = (data.get("auth_token") or "").strip()   # pre-derived by client
    make_admin = bool(data.get("make_admin", False))

    if not new_user or not auth_token:
        return jsonify({"error": "Username and auth token required"}), 400
    if not valid_username(new_user):
        return jsonify({"error": "Username: 1-32 alphanumeric/underscore only"}), 400

    users = get_users()
    if new_user in users:
        return jsonify({"error": f'User "{new_user}" already exists'}), 409

    users[new_user] = hash_auth_token(auth_token)
    write_users(users)

    if make_admin:
        set_admin(new_user)

    return jsonify({"ok": True, "username": new_user, "is_admin": new_user == get_admin()})

@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    err = require_admin()
    if err: return err

    data     = request.get_json()
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Username required"}), 400
    if username == get_admin():
        return jsonify({"error": "Cannot delete the admin account"}), 400

    users = get_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404

    del users[username]
    write_users(users)

    # Remove their key bundle too
    bundle_path = os.path.join(KEY_BUNDLE_DIR, f"{username}.bundle")
    if os.path.exists(bundle_path):
        os.remove(bundle_path)

    return jsonify({"ok": True})

@app.route("/admin/set-admin", methods=["POST"])
def admin_set_admin():
    err = require_admin()
    if err: return err

    data     = request.get_json()
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Username required"}), 400

    users = get_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404

    set_admin(username)
    return jsonify({"ok": True, "new_admin": username})

@app.route("/admin/force-logout", methods=["POST"])
def admin_force_logout():
    err = require_admin()
    if err: return err

    new_key = secrets.token_hex(32)
    set_key(ENV_FILE, "SECRET_KEY", new_key)
    os.environ["SECRET_KEY"] = new_key
    app.secret_key = new_key

    session_dir = app.config["SESSION_FILE_DIR"]
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir)
        os.makedirs(session_dir, exist_ok=True)

    session.clear()
    return jsonify({"ok": True})


@app.route("/admin/update-nuke-command", methods=["POST"])
def admin_update_nuke_command():
    err = require_admin()
    if err: return err 

    data = request.get_json()
    new_command = (data.get("command") or "").strip()

    if not new_command.startswith("/"):
        new_command = "/" + new_command

    if not re.match(r'^/[A-Z0-9_]+$', new_command):
        return jsonify({error: "Command must be uppercase letters, numbers or underscores only"}), 400

    set_key(ENV_FILE, "NUKE_COMMAND", new_command)
    os.environ["NUKE_COMMAND"] = new_command

    return jsonify({"ok": True, "new_command": new_command})


# ─── Setup helper ─────────────────────────────────────────────────────────────
# Run once to create the first admin user from .env BOOTSTRAP_USER/PASS.
# After first run, remove BOOTSTRAP_USER and BOOTSTRAP_PASS from .env.

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """
    One-time setup endpoint. Only works when USERS env var is empty.
    POST JSON: { username, auth_token, make_admin: true }
    """
    users = get_users()
    if users:
        return jsonify({"error": "Setup already complete"}), 403
    if request.method == "GET":
        return render_template("setup.html")

    data       = request.get_json()
    username   = (data.get("username") or "").strip()
    auth_token = (data.get("auth_token") or "").strip()

    if not username or not auth_token:
        return jsonify({"error": "Username and auth token required"}), 400
    if not valid_username(username):
        return jsonify({"error": "Invalid username"}), 400

    users[username] = hash_auth_token(auth_token)
    write_users(users)
    set_admin(username)

    return jsonify({"ok": True})


if __name__ == "__main__":

    try:
        os.makedirs("static", exist_ok=True)
        app.run(host="0.0.0.0", port=5000, debug=False)
    except KeyboardInterrupt:
        print("=" * 38)
        print("SERVER STOPPED!")
        print("EXITING")
        time.sleep(3)
        sys.exit(0)
