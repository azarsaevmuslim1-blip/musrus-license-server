import functools
import html as html_mod
from datetime import datetime, timezone

from flask import Flask, jsonify, request, session, redirect, url_for, render_template_string
from flask_cors import CORS

from config import ADMIN_KEY, ADMIN_PASSWORD, SECRET_KEY
from database import (
    init_db, create_license_key, get_license,
    activate_license, verify_license, reset_hwid,
    revoke_license, get_all_licenses,
    delete_license, clear_all_licenses,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app)

with app.app_context():
    init_db()


def require_admin_key(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        key = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else request.args.get("admin_key", "")
        if key != ADMIN_KEY:
            return jsonify({"success": False, "error": "forbidden", "message": "Неверный ключ администратора"}), 403
        return f(*args, **kwargs)
    return wrapper


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()

    if not license_key or not hwid:
        return jsonify({"success": False, "error": "bad_request", "message": "license_key и hwid обязательны"}), 400

    result = activate_license(license_key, hwid)
    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()

    if not license_key or not hwid:
        return jsonify({"valid": False, "error": "bad_request", "message": "license_key и hwid обязательны"}), 400

    result = verify_license(license_key, hwid)
    status = 200 if result["valid"] else 400
    return jsonify(result), status


@app.route("/api/admin/reset", methods=["POST"])
@require_admin_key
def api_admin_reset():
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip().upper()
    if not license_key:
        return jsonify({"success": False, "error": "bad_request", "message": "license_key обязателен"}), 400
    result = reset_hwid(license_key)
    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/admin/revoke", methods=["POST"])
@require_admin_key
def api_admin_revoke():
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip().upper()
    if not license_key:
        return jsonify({"success": False, "error": "bad_request", "message": "license_key обязателен"}), 400
    result = revoke_license(license_key)
    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/admin/create", methods=["POST"])
@require_admin_key
def api_admin_create():
    data = request.get_json(force=True) or {}
    days = data.get("days")
    if days is not None:
        days = int(days)
        if days not in (30, 60, 365, 3650):
            return jsonify({"success": False, "error": "bad_request", "message": "Допустимые значения: 30, 60, 365, 3650"}), 400
    result = create_license_key(days)
    return jsonify({"success": True, "key": result["license_key"], "expires_at": result.get("expires_at")})


@app.route("/api/admin/keys", methods=["GET"])
@require_admin_key
def api_admin_keys():
    keys = get_all_licenses()
    return jsonify({"success": True, "keys": keys})


@app.route("/api/admin/delete", methods=["POST"])
@require_admin_key
def api_admin_delete():
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip().upper()
    if not license_key:
        return jsonify({"success": False, "error": "bad_request", "message": "license_key обязателен"}), 400
    result = delete_license(license_key)
    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/admin/clear_all", methods=["POST"])
@require_admin_key
def api_admin_clear_all():
    result = clear_all_licenses()
    return jsonify(result)


# ─── Admin Panel Routes ───────────────────────────────────────────────────────

ADMIN_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="ru" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MusRus Admin</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { display: flex; align-items: center; min-height: 100vh; background: #0a0a0f; }
    .card { background: #161622; border: 1px solid #2a2a3a; width: 100%; max-width: 400px; }
    .form-control { background: #0a0a0f; border-color: #2a2a3a; color: #fff; }
    .form-control:focus { background: #0a0a0f; border-color: #6f42c1; box-shadow: 0 0 0 .2rem rgba(111,66,193,.25); }
    .btn-primary { background: #6f42c1; border-color: #6f42c1; }
    .btn-primary:hover { background: #5a32a3; border-color: #5a32a3; }
  </style>
</head>
<body>
  <div class="container d-flex justify-content-center">
    <div class="card p-4">
      <h3 class="text-center mb-3 text-light">🔐 MusRus Admin</h3>
      <form method="post" action="/admin/login">
        <div class="mb-3">
          <label class="form-label text-secondary">Password</label>
          <input type="password" name="password" class="form-control" required autofocus>
        </div>
        <button type="submit" class="btn btn-primary w-100">Войти</button>
      </form>
      {% if error %}
        <div class="alert alert-danger mt-3 py-2 small">{{ error }}</div>
      {% endif %}
    </div>
  </div>
</body>
</html>"""

ADMIN_PANEL_PAGE = """<!DOCTYPE html>
<html lang="ru" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MusRus Admin — Панель управления</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    body { background: #0a0a0f; color: #e0e0e0; }
    .navbar { background: #161622 !important; border-bottom: 1px solid #2a2a3a; }
    .card { background: #161622; border: 1px solid #2a2a3a; }
    .table { color: #e0e0e0; }
    .table-dark { --bs-table-bg: #161622; --bs-table-striped-bg: #1a1a2e; }
    .badge-hwid { font-family: monospace; font-size: 11px; }
    .btn-hwid { font-size: 12px; padding: 2px 8px; }
    .form-control, .form-select { background: #0a0a0f; border-color: #2a2a3a; color: #fff; }
    .form-control:focus, .form-select:focus { background: #0a0a0f; border-color: #6f42c1; box-shadow: 0 0 0 .2rem rgba(111,66,193,.25); }
    .modal-content { background: #161622; border: 1px solid #2a2a3a; }
    .btn-close { filter: invert(1); }
    .toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; }
  </style>
</head>
<body>
  <nav class="navbar navbar-dark px-3">
    <span class="navbar-brand mb-0"><i class="bi bi-shield-check"></i> MusRus License Admin</span>
    <div>
      <span class="text-secondary me-3 small">{{ now }}</span>
      <a href="/admin/logout" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i> Выйти</a>
    </div>
  </nav>

  <div class="container-fluid p-3">
    <!-- Create Key -->
    <div class="card mb-3 p-3">
      <div class="row g-2 align-items-end">
        <div class="col-auto">
          <h6 class="mb-0 text-light"><i class="bi bi-key"></i> Создать ключ</h6>
        </div>
        <div class="col-auto">
          <select id="keyDays" class="form-select form-select-sm">
            <option value="30">30 дней</option>
            <option value="60">60 дней</option>
            <option value="365">1 год</option>
            <option value="3650">Бессрочный</option>
          </select>
        </div>
        <div class="col-auto">
          <button class="btn btn-primary btn-sm" onclick="createKey()"><i class="bi bi-plus-lg"></i> Создать</button>
        </div>
        <div class="col-auto">
          <span id="createResult" class="small text-success ms-2"></span>
        </div>
      </div>
    </div>

    <!-- Keys Table -->
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-table"></i> Все ключи <span class="badge bg-secondary" id="keyCount">0</span></span>
        <div>
          <button class="btn btn-sm btn-outline-danger me-2" onclick="clearAllKeys()" title="Удалить все ключи">
            <i class="bi bi-trash3"></i> Очистить все
          </button>
          <button class="btn btn-sm btn-outline-secondary" onclick="loadKeys()"><i class="bi bi-arrow-clockwise"></i></button>
        </div>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-dark table-striped table-hover mb-0 small">
            <thead>
              <tr>
                <th>#</th>
                <th>License Key</th>
                <th>HWID</th>
                <th>Статус</th>
                <th>Активирован</th>
                <th>Истекает</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody id="keysBody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast-container">
    <div id="toast" class="toast align-items-center text-bg-dark border-0" role="alert">
      <div class="d-flex">
        <div class="toast-body" id="toastMsg"></div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const ADMIN_KEY = '{{ admin_key }}';
    const toast = new bootstrap.Toast(document.getElementById('toast'));

    function showToast(msg, ok=true) {
      document.getElementById('toastMsg').textContent = (ok ? '✅ ' : '❌ ') + msg;
      document.getElementById('toast').className = 'toast align-items-center border-0 text-bg-' + (ok ? 'dark' : 'danger');
      toast.show();
    }

    async function api(method, path, body) {
      const opts = { method, headers: {'Authorization': 'Bearer ' + ADMIN_KEY, 'Content-Type': 'application/json'} };
      if (body) opts.body = JSON.stringify(body);
      const r = await fetch(path, opts);
      return r.json();
    }

    async function loadKeys() {
      const data = await api('GET', '/api/admin/keys');
      if (!data.success) { showToast(data.message || 'Ошибка загрузки', false); return; }
      const tbody = document.getElementById('keysBody');
      tbody.innerHTML = '';
      document.getElementById('keyCount').textContent = data.keys.length;
      data.keys.forEach((k, i) => {
        const hwid = k.hwid || '<span class="text-secondary">—</span>';
        const hwidShort = k.hwid ? k.hwid.substring(0, 16) + '...' : '—';
        const status = k.is_active ? '<span class="text-success"><i class="bi bi-check-circle"></i> Active</span>'
                                    : '<span class="text-danger"><i class="bi bi-x-circle"></i> Revoked</span>';
        const activated = k.activated_at ? new Date(k.activated_at).toLocaleString('ru-RU') : '<span class="text-secondary">—</span>';
        const expires = k.expires_at ? new Date(k.expires_at).toLocaleString('ru-RU') : '<span class="text-secondary">∞</span>';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${i+1}</td>
          <td><code>${k.license_key}</code></td>
          <td><span title="${k.hwid || ''}">${hwidShort}</span></td>
          <td>${status}</td>
          <td>${activated}</td>
          <td>${expires}</td>
          <td>
            <button class="btn btn-warning btn-sm btn-hwid" onclick="resetHwid('${k.license_key}')" title="Сбросить HWID">
              <i class="bi bi-arrow-counterclockwise"></i> HWID
            </button>
            ${k.is_active ? `<button class="btn btn-danger btn-sm btn-hwid" onclick="revokeKey('${k.license_key}')" title="Отозвать">
              <i class="bi bi-x-lg"></i>
            </button>` : ''}
            <button class="btn btn-outline-danger btn-sm btn-hwid" onclick="deleteKey('${k.license_key}')" title="Удалить навсегда">
              <i class="bi bi-trash"></i>
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function resetHwid(key) {
      if (!confirm('Сбросить HWID для ' + key + '?')) return;
      const data = await api('POST', '/api/admin/reset', { license_key: key });
      showToast(data.message, data.success);
      if (data.success) loadKeys();
    }

    async function revokeKey(key) {
      if (!confirm('Отозвать ключ ' + key + '?')) return;
      const data = await api('POST', '/api/admin/revoke', { license_key: key });
      showToast(data.message, data.success);
      if (data.success) loadKeys();
    }

    async function createKey() {
      const days = parseInt(document.getElementById('keyDays').value);
      const data = await api('POST', '/api/admin/create', { days });
      if (data.success) {
        document.getElementById('createResult').textContent = '✅ ' + data.key;
        showToast('Ключ создан: ' + data.key);
        loadKeys();
      } else {
        showToast(data.message, false);
      }
    }

    async function deleteKey(key) {
      if (!confirm('Удалить ключ ' + key + ' навсегда?')) return;
      const data = await api('POST', '/api/admin/delete', { license_key: key });
      showToast(data.message, data.success);
      if (data.success) loadKeys();
    }

    async function clearAllKeys() {
      if (!confirm('Вы уверены, что хотите удалить ВСЕ ключи? Это действие необратимо!')) return;
      const data = await api('POST', '/api/admin/clear_all');
      showToast(data.message, data.success);
      if (data.success) loadKeys();
    }

    loadKeys();
    setInterval(loadKeys, 30000);
  </script>
</body>
</html>"""


@app.route("/admin", methods=["GET"])
def admin_index():
    if session.get("logged_in"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return render_template_string(ADMIN_PANEL_PAGE, now=now, admin_key=ADMIN_KEY)
    return redirect(url_for("admin_login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["logged_in"] = True
            session.permanent = True
            return redirect(url_for("admin_index"))
        error = "Неверный пароль"
    return render_template_string(ADMIN_LOGIN_PAGE, error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/")
def index():
    return jsonify({
        "service": "MusRus License Server",
        "version": "2.0",
        "endpoints": [
            "POST /api/activate",
            "POST /api/verify",
            "POST /api/admin/reset",
            "POST /api/admin/revoke",
            "POST /api/admin/create",
            "POST /api/admin/delete",
            "POST /api/admin/clear_all",
            "GET /api/admin/keys",
            "GET /admin",
        ]
    })


if __name__ == "__main__":
    init_db()
    print("Server starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
