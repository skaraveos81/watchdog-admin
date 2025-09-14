from flask import make_response, abort
import os, base64, json, re
from flask import Flask, request, redirect, session, url_for, render_template_string, flash
import requests

# ====== ΡΥΘΜΙΣΕΙΣ ======
# Τα βάζεις ως env vars στο hosting (Render/Railway/Heroku)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "change-me")  # βάλε δυνατό κωδικό
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

# GitHub repo στο οποίο είναι το project (π.χ. "myorg/delivery-watchdog")
GH_REPO   = os.getenv("GH_REPO", "")
GH_BRANCH = os.getenv("GH_BRANCH", "main")
# GitHub Personal Access Token (fine-grained) με δικαιώματα "Contents: Read & Write"
GH_TOKEN  = os.getenv("GH_TOKEN", "")

# Ποια αρχεία διαχειρίζεται
PATH_CONFIG       = "config.json"
PATH_COMPETITORS  = "competitors.json"
PATH_EFOOD        = "efood.json"
PATH_WORKFLOW     = ".github/workflows/watchdog.yml"
DIR_REPORTS       = "reports"

# ====== APP ======
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- GitHub helpers ----------
def gh_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GH_TOKEN}",
    }

def gh_get_content(path):
    url = f"https://api.github.com/repos/{GH_REPO}/contents/{path}?ref={GH_BRANCH}"
    r = requests.get(url, headers=gh_headers(), timeout=30)
    r.raise_for_status()
    data = r.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    sha = data["sha"]
    return content, sha

def gh_put_content(path, text, sha=None, message="admin update"):
    url = f"https://api.github.com/repos/{GH_REPO}/contents/{path}"
    body = {
        "message": message,
        "content": base64.b64encode(text.encode("utf-8")).decode("utf-8"),
        "branch": GH_BRANCH,
    }
    if sha:
        body["sha"] = sha
    r = requests.put(url, headers=gh_headers(), json=body, timeout=30)
    r.raise_for_status()
    return r.json()

def gh_list_dir(path):
    url = f"https://api.github.com/repos/{GH_REPO}/contents/{path}?ref={GH_BRANCH}"
    r = requests.get(url, headers=gh_headers(), timeout=30)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return r.json()

# ---------- Auth ----------
def logged_in():
    return session.get("auth") == True

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["auth"] = True
            return redirect(url_for("dashboard"))
        flash("Λάθος στοιχεία.")
    return render_template_string(TEMPLATE_LOGIN)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Pages ----------
@app.route("/")
def dashboard():
    if not logged_in(): return redirect(url_for("login"))
    try:
        cfg_text, _ = gh_get_content(PATH_CONFIG)
        cfg = json.loads(cfg_text)
        cities = cfg.get("cities", [])
        email_enabled = cfg.get("email_enabled", True)
        mail_to = cfg.get("mail_to","(ορίζεται εδώ)")
        user_agent = cfg.get("user_agent","")
        reports = gh_list_dir(DIR_REPORTS)
        report_files = sorted([x["name"] for x in reports if x["type"]=="file"], reverse=True)[:20]
    except Exception as e:
        flash(f"Σφάλμα φόρτωσης: {e}")
        cities, email_enabled, mail_to, user_agent, report_files = [], True, "", "", []
    return render_template_string(TEMPLATE_DASHBOARD,
                                  cities=cities, email_enabled=email_enabled,
                                  mail_to=mail_to, user_agent=user_agent,
                                  report_files=report_files)

@app.route("/competitors", methods=["GET","POST"])
def competitors():
    if not logged_in(): return redirect(url_for("login"))
    if request.method == "POST":
        # σώσε JSON που ήρθε από το textarea
        try:
            body = request.form.get("json","{}")
            data = json.loads(body)
            _, sha = gh_get_content(PATH_COMPETITORS)
            gh_put_content(PATH_COMPETITORS, json.dumps(data, ensure_ascii=False, indent=2),
                           sha=sha, message="admin: update competitors.json")
            flash("Αποθηκεύτηκε.")
        except Exception as e:
            flash(f"Σφάλμα: {e}")
        return redirect(url_for("competitors"))
    # GET
    try:
        text, _ = gh_get_content(PATH_COMPETITORS)
    except Exception:
        text = "{\n  \"Βέροια\": []\n}\n"
    return render_template_string(TEMPLATE_JSON_EDITOR,
                                  title="Competitors ανά πόλη",
                                  action=url_for("competitors"),
                                  json_text=text,
                                  helper="Λίστα από αντικείμενα {name, url} ανά πόλη.")

@app.route("/efood", methods=["GET","POST"])
def efood():
    if not logged_in(): return redirect(url_for("login"))
    if request.method == "POST":
        try:
            body = request.form.get("json","{}")
            data = json.loads(body)
            _, sha = gh_get_content(PATH_EFOOD)
            gh_put_content(PATH_EFOOD, json.dumps(data, ensure_ascii=False, indent=2),
                           sha=sha, message="admin: update efood.json")
            flash("Αποθηκεύτηκε.")
        except Exception as e:
            flash(f"Σφάλμα: {e}")
        return redirect(url_for("efood"))
    try:
        text, _ = gh_get_content(PATH_EFOOD)
    except Exception:
        text = "{\n  \"Βέροια\": []\n}\n"
    return render_template_string(TEMPLATE_JSON_EDITOR,
                                  title="efood URLs ανά πόλη",
                                  action=url_for("efood"),
                                  json_text=text,
                                  helper="Λίστα από αντικείμενα {name, url} ανά πόλη (σελίδες efood).")

@app.route("/config", methods=["GET","POST"])
def config():
    if not logged_in(): return redirect(url_for("login"))
    if request.method == "POST":
        try:
            cities = [c.strip() for c in request.form.get("cities","").split(",") if c.strip()]
            email_enabled = request.form.get("email_enabled") == "on"
            mail_to = request.form.get("mail_to","").strip()
            user_agent = request.form.get("user_agent","").strip()

            text, sha = gh_get_content(PATH_CONFIG)
            cfg = json.loads(text)
            cfg["cities"] = cities
            cfg["email_enabled"] = email_enabled
            cfg["mail_to"] = mail_to
            if user_agent: cfg["user_agent"] = user_agent

            gh_put_content(PATH_CONFIG, json.dumps(cfg, ensure_ascii=False, indent=2),
                           sha=sha, message="admin: update config.json")
            flash("Αποθηκεύτηκε το config.")
        except Exception as e:
            flash(f"Σφάλμα: {e}")
        return redirect(url_for("config"))

    # GET
    try:
        text, _ = gh_get_content(PATH_CONFIG)
        cfg = json.loads(text)
        cities = ", ".join(cfg.get("cities", []))
        email_enabled = cfg.get("email_enabled", True)
        mail_to = cfg.get("mail_to","")
        user_agent = cfg.get("user_agent","")
    except Exception:
        cities, email_enabled, mail_to, user_agent = "", True, "", ""
    return render_template_string(TEMPLATE_CONFIG,
                                  cities=cities, email_enabled=email_enabled,
                                  mail_to=mail_to, user_agent=user_agent)

@app.route("/workflow", methods=["GET","POST"])
def workflow():
    if not logged_in(): return redirect(url_for("login"))
    if request.method == "POST":
        try:
            cron = request.form.get("cron","0 6 * * *").strip()
            text, sha = gh_get_content(PATH_WORKFLOW)
            # αντικατάσταση της γραμμής cron
            new_text = re.sub(r'cron:\s*".*?"', f'cron: "{cron}"', text)
            gh_put_content(PATH_WORKFLOW, new_text, sha=sha, message="admin: update cron")
            flash("Ενημερώθηκε το cron στο workflow.")
        except Exception as e:
            flash(f"Σφάλμα: {e}")
        return redirect(url_for("workflow"))

    # GET
    try:
        text, _ = gh_get_content(PATH_WORKFLOW)
        m = re.search(r'cron:\s*"([^"]+)"', text)
        cron = m.group(1) if m else "0 6 * * *"
    except Exception:
        cron = "0 6 * * *"
    return render_template_string(TEMPLATE_WORKFLOW, cron=cron)

@app.route("/reports")
def reports():
    if not logged_in(): return redirect(url_for("login"))
    files = gh_list_dir(DIR_REPORTS)
    files = sorted([x for x in files if x["type"]=="file"], key=lambda x: x["name"], reverse=True)[:50]
    return render_template_string(TEMPLATE_REPORTS, files=files, repo=GH_REPO, branch=GH_BRANCH)

@app.route("/report/<name>")
def report_view(name):
    if not logged_in(): 
        return redirect(url_for("login"))
    name = _safe_name(name)

    # διαβάζουμε το περιεχόμενο από το repo
    try:
        text, _ = gh_get_content(f"{DIR_REPORTS}/{name}")
    except Exception as e:
        flash(f"Σφάλμα ανάγνωσης: {e}")
        return redirect(url_for("reports"))

    # HTML report -> εμφάνιση inline
    if name.endswith(".html"):
        csv_guess = name.replace(".html", ".csv")
        # έλεγχος αν υπάρχει και CSV δίπλα (προαιρετικός)
        has_csv = False
        try:
            _ = gh_get_content(f"{DIR_REPORTS}/{csv_guess}")
            has_csv = True
        except Exception:
            pass
        return render_template_string(TEMPLATE_REPORT_VIEW,
                                      title=name,
                                      html=text,
                                      csv_name=csv_guess if has_csv else None)

    # Markdown -> απλή προεπισκόπηση (χωρίς επιπλέον libs)
    if name.endswith(".md"):
        safe = (
            text.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;")
        )
        return render_template_string(TEMPLATE_REPORT_MD,
                                      title=name,
                                      md_pre=safe)

    # Άλλο τύπος (π.χ. .csv) -> κατέβασμα
    return redirect(url_for("download_report", name=name))


SAFE_NAME_RE = re.compile(r'^[\w\-.]+$')  # a-zA-Z0-9 _ - .
def _safe_name(name: str) -> str:
    if not SAFE_NAME_RE.match(name or ""):
        abort(400)  # απορρίπτει path traversal
    return name

# ---------- Templates ----------
TEMPLATE_BASE = """
<!doctype html>
<html lang="el"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Delivery Watchdog — Admin</title>
<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2/css/pico.min.css">
<style> body{max-width:1100px;margin:auto} textarea{min-height:360px} .badge{font-size:.85rem} </style>
</head><body>
<nav class="container-fluid">
  <ul>
    <li><strong>Watchdog Admin</strong></li>
  </ul>
  <ul>
    {% if session.get('auth') %}
    <li><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
    <li><a href="{{ url_for('competitors') }}">Competitors</a></li>
    <li><a href="{{ url_for('efood') }}">efood</a></li>
    <li><a href="{{ url_for('config') }}">Config</a></li>
    <li><a href="{{ url_for('workflow') }}">Schedule</a></li>
    <li><a href="{{ url_for('reports') }}">Reports</a></li>
    <li><a href="{{ url_for('logout') }}">Logout</a></li>
    {% endif %}
  </ul>
</nav>
<main class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}<article>{% for m in messages %}<p>{{ m }}</p>{% endfor %}</article>{% endif %}
  {% endwith %}
  {{ body|safe }}
</main>
</body></html>
"""

TEMPLATE_LOGIN = """
<!doctype html><html lang="el"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — Watchdog</title>
<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2/css/pico.min.css">
</head><body class="container">
  <h2>Σύνδεση</h2>
  <form method="post">
    <label>Χρήστης <input name="username" required></label>
    <label>Κωδικός <input type="password" name="password" required></label>
    <button type="submit">Είσοδος</button>
  </form>
</body></html>
"""

TEMPLATE_DASHBOARD = TEMPLATE_BASE.replace("{{ body|safe }}", """
<h2>Dashboard</h2>
<div class="grid">
  <article>
    <h3>Ρυθμίσεις</h3>
    <p><span class="badge">Email</span> {{ 'Ενεργό' if email_enabled else 'Απενεργό' }}</p>
    <p><span class="badge">MAIL_TO</span> {{ mail_to or '-' }}</p>
    <p><span class="badge">User-Agent</span> {{ user_agent or '-' }}</p>
    <p><span class="badge">Πόλεις</span> {{ ', '.join(cities) if cities else '-' }}</p>
  </article>
  <article>
    <h3>Reports (τελευταία)</h3>
    {% if report_files %}
      <ul>
        {% for f in report_files %}<li>{{ f }}</li>{% endfor %}
      </ul>
      <p><a href="{{ url_for('reports') }}">Δες όλα</a></p>
    {% else %}
      <p>Δεν βρέθηκαν reports.</p>
    {% endif %}
  </article>
</div>
""")

TEMPLATE_JSON_EDITOR = TEMPLATE_BASE.replace("{{ body|safe }}", """
<h2>{{ title }}</h2>
<p class="secondary">{{ helper }}</p>
<form method="post">
  <label>JSON
    <textarea name="json">{{ json_text }}</textarea>
  </label>
  <button type="submit">Αποθήκευση</button>
</form>
""")

TEMPLATE_CONFIG = TEMPLATE_BASE.replace("{{ body|safe }}", """
<h2>Config</h2>
<form method="post">
  <label>Πόλεις (comma-separated)
    <input name="cities" value="{{ cities }}">
  </label>
  <label><input type="checkbox" name="email_enabled" {% if email_enabled %}checked{% endif %}> Email ενεργό</label>
  <label>MAIL_TO (comma-separated)
    <input name="mail_to" value="{{ mail_to }}">
  </label>
  <label>User-Agent (προαιρετικό)
    <input name="user_agent" value="{{ user_agent }}">
  </label>
  <button type="submit">Αποθήκευση</button>
</form>
""")

TEMPLATE_WORKFLOW = TEMPLATE_BASE.replace("{{ body|safe }}", """
<h2>Schedule (GitHub Actions)</h2>
<form method="post">
  <label>cron (UTC)
    <input name="cron" value="{{ cron }}" placeholder="0 6 * * *">
  </label>
  <button type="submit">Αποθήκευση</button>
</form>
<p class="secondary">Παράδειγμα: 06:00 UTC ≈ 09:00 Ελλάδας (χειμ./θερινή ώρα μπορεί να διαφέρει).</p>
""")

TEMPLATE_REPORTS = TEMPLATE_BASE.replace("{{ body|safe }}", """
<h2>Reports</h2>
{% if files %}
  <ul>
  {% for f in files %}
    <li><a href="https://raw.githubusercontent.com/{{ repo }}/{{ branch }}/reports/{{ f['name'] }}" target="_blank">{{ f["name"] }}</a></li>
  {% endfor %}
  </ul>
{% else %}
  <p>Δεν υπάρχουν reports ακόμη.</p>
{% endif %}
""")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))


