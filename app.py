import os, sqlite3, secrets, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory

APP_NAME = "CareWhistle"
BASE_DIR = os.path.dirname(__file__)
DB_PATH  = os.path.join(BASE_DIR, "carewhistle.db")
MEDIA_DIR= os.path.join(BASE_DIR, "media")

STATUSES   = ["new","in_review","awaiting_info","resolved","closed"]
CATEGORIES = ["Bribery","Fraud","Harassment","GDPR","Safety","Money laundering","Other"]

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY","dev-key-change-me")

def now_iso(): return datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z"
def now(): return now_iso()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db=get_db(); c=db.cursor()
    c.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS companies(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      company_code TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN('admin','manager')),
      company_id INTEGER,
      created_at TEXT NOT NULL,
      FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      company_id INTEGER NOT NULL,
      subject TEXT NOT NULL,
      content TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      case_code TEXT NOT NULL UNIQUE,
      pin TEXT NOT NULL,
      what_done TEXT,
      want_feedback TEXT,
      contact TEXT,
      memorable TEXT,
      mode TEXT NOT NULL,
      assignee_user_id INTEGER,
      FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE,
      FOREIGN KEY(assignee_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      channel TEXT NOT NULL CHECK(channel IN('public','internal')),
      sender TEXT NOT NULL CHECK(sender IN('admin','reporter','manager')),
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      user_id INTEGER,
      FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      created_at TEXT NOT NULL,
      read_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS content_blocks(key TEXT PRIMARY KEY, body TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
    """)
    # seed once
    if c.execute("SELECT COUNT(*) FROM companies").fetchone()[0]==0:
        c.execute("INSERT INTO companies(name,company_code,created_at) VALUES(?,?,?)", ("Bright Care","BRI123",now_iso()))
        c.execute("INSERT INTO companies(name,company_code,created_at) VALUES(?,?,?)", ("CycleSoft","CYC999",now_iso()))
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0:
        from werkzeug.security import generate_password_hash
        c.execute("INSERT INTO users(email,password_hash,role,company_id,created_at) VALUES (?,?,?,?,?)",
                  ("info@carewhistle.com", generate_password_hash("Aireville122"), "admin", None, now_iso()))
        # demo manager
        c.execute("INSERT INTO users(email,password_hash,role,company_id,created_at) VALUES (?,?,?,?,?)",
                  ("manager@brightcare.com", generate_password_hash("manager123"), "manager",
                   c.execute("SELECT id FROM companies WHERE company_code='BRI123'").fetchone()[0], now_iso()))
    if c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]==0:
        import random
        comp = c.execute("SELECT id FROM companies WHERE company_code='BRI123'").fetchone()[0]
        for i in range(8):
            case = secrets.token_urlsafe(8); pin = str(secrets.randbelow(900000)+100000)
            c.execute("""INSERT INTO reports(company_id,subject,content,category,status,created_at,case_code,pin,what_done,want_feedback,contact,memorable,mode,assignee_user_id)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                      (comp, f"Demo incident {i+1}", "Demo description body", random.choice(CATEGORIES),
                       random.choice(STATUSES), now_iso(), case, pin, "", "Yes", "", "word", "anonymous"))
            rid=c.lastrowid
            c.execute("INSERT INTO messages(report_id,channel,sender,body,created_at) VALUES (?,?,?,?,?)",
                      (rid,"public","reporter","Hello, I prefer to stay anonymous.",now_iso()))
    db.commit(); db.close()

# --------------------- helpers ---------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def _w(*a,**k):
        if not session.get("user_id"): return redirect(url_for("login", next=request.path))
        return f(*a,**k)
    return _w

def role_required(*roles):
    from functools import wraps
    def deco(f):
        @wraps(f)
        def _w(*a,**k):
            if session.get("role") not in roles: abort(403)
            return f(*a,**k)
        return _w
    return deco

def current_user():
    if not session.get("user_id"): return None
    return {"id":session["user_id"], "email":session["email"], "role":session["role"], "company_id":session.get("company_id")}

@app.context_processor
def inject_now():
    return {"now": now}

# --------------------- public ---------------------
@app.route("/")
def home(): return render_template("home.html", title="Home")

@app.route("/how")
def how(): return render_template("how.html", title="How it works")

@app.route("/pricing")
def pricing(): return render_template("pricing.html", title="Plans & Pricing")

@app.route("/report", methods=["GET","POST"])
def report():
    import random
    if request.method=="GET":
        a,b = random.randint(1,9), random.randint(1,9)
        session["captcha_answer"]=str(a+b)
        return render_template("report.html", categories=CATEGORIES, captcha_a=a, captcha_b=b, title="Make a Report")
    # POST
    if (request.form.get("captcha") or "").strip()!=session.get("captcha_answer"):
        flash("CAPTCHA incorrect.","danger"); return redirect(url_for("report"))
    company_code=(request.form.get("company_code") or "").strip().upper()
    db=get_db(); c=db.cursor()
    comp=c.execute("SELECT id FROM companies WHERE company_code=?",(company_code,)).fetchone()
    if not comp:
        db.close(); flash("Unknown company code.","danger"); return redirect(url_for("report"))
    subject=(request.form.get("subject") or "").strip()
    content=(request.form.get("content") or "").strip()
    category=(request.form.get("category") or "Other").strip()
    what_done=request.form.get("what_done") or ""
    want_feedback=request.form.get("want_feedback") or ""
    contact=request.form.get("contact") or ""
    memorable=request.form.get("memorable") or ""
    mode=(request.form.get("mode") or "anonymous")
    case_code=secrets.token_urlsafe(9)
    pin=str(secrets.randbelow(900000)+100000)
    c.execute("""INSERT INTO reports(company_id,subject,content,category,status,created_at,case_code,pin,what_done,want_feedback,contact,memorable,mode,assignee_user_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
              (comp["id"],subject,content,category,"new",now_iso(),case_code,pin,what_done,want_feedback,contact,memorable,mode))
    rid=c.lastrowid
    c.execute("INSERT INTO messages(report_id,channel,sender,body,created_at) VALUES (?,?,?,?,?)",
              (rid,"public","reporter","Report submitted.",now_iso()))
    db.commit(); db.close()
    return render_template("report_success.html", case_code=case_code, pin=pin, title="Report submitted")

@app.route("/follow", methods=["GET","POST"])
def follow():
    if request.method=="POST":
        code=(request.form.get("case_code") or "").strip()
        pin=(request.form.get("pin") or "").strip()
        db=get_db(); r=db.execute("SELECT * FROM reports WHERE case_code=? AND pin=?", (code,pin)).fetchone()
        db.close()
        if not r: flash("Invalid case code or PIN.","danger"); return redirect(url_for("follow"))
        session.setdefault("report_access",{})[code]=pin; session.modified=True
        return redirect(url_for("follow_thread", case_code=code))
    return render_template("follow.html", title="Follow your case")

def reporter_access_required(f):
    from functools import wraps
    @wraps(f)
    def _w(case_code,*a,**k):
        if session.get("report_access",{}).get(case_code) is None: return redirect(url_for("follow"))
        return f(case_code,*a,**k)
    return _w

@app.route("/follow/<case_code>")
@reporter_access_required
def follow_thread(case_code):
    db=get_db()
    r=db.execute("""SELECT r.*, c.company_code FROM reports r JOIN companies c ON c.id=r.company_id WHERE case_code=?""",(case_code,)).fetchone()
    msgs=db.execute("SELECT * FROM messages WHERE report_id=? AND channel='public' ORDER BY created_at",(r["id"],)).fetchall()
    db.close()
    return render_template("follow_thread.html", r=r, msgs=msgs, title="Case")

@app.route("/follow/<case_code>/message", methods=["POST"])
@reporter_access_required
def follow_message(case_code):
    body=(request.form.get("body") or "").strip()
    if not body: return redirect(url_for("follow_thread", case_code=case_code))
    db=get_db(); r=db.execute("SELECT id FROM reports WHERE case_code=?", (case_code,)).fetchone()
    db.execute("INSERT INTO messages(report_id,channel,sender,body,created_at) VALUES (?,?,?,?,?)",
               (r["id"],"public","reporter",body,now_iso()))
    db.commit(); db.close()
    flash("Message sent.","success")
    return redirect(url_for("follow_thread", case_code=case_code))

# --------------------- auth ---------------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=(request.form.get("email") or "").strip().lower()
        pw=request.form.get("password") or ""
        db=get_db(); u=db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            db.close(); flash("Invalid credentials.","danger"); return render_template("login.html", title="Login")
        from werkzeug.security import check_password_hash
        if not check_password_hash(u["password_hash"], pw):
            db.close(); flash("Invalid credentials.","danger"); return render_template("login.html", title="Login")
        session.update({"user_id":u["id"],"email":u["email"],"role":u["role"],"company_id":u["company_id"]})
        db.close()
        return redirect(url_for("admin_overview" if u["role"]=="admin" else "manager_overview"))
    return render_template("login.html", title="Login")

@app.route("/logout")
def logout(): session.clear(); flash("Logged out.","info"); return redirect(url_for("home"))

# --------------------- admin ---------------------
@app.route("/admin")
@login_required
@role_required("admin")
def admin_overview():
    db=get_db()
    k=db.execute("""SELECT
      SUM(CASE WHEN status='new' THEN 1 ELSE 0 END),
      SUM(CASE WHEN status IN('in_review','awaiting_info') THEN 1 ELSE 0 END),
      SUM(CASE WHEN status IN('resolved','closed') THEN 1 ELSE 0 END)
    FROM reports""").fetchone()
    kpis={"new":k[0] or 0,"inproc":k[1] or 0,"closed":k[2] or 0,"avg_hrs":0}
    month=db.execute("SELECT substr(created_at,1,7) ym, COUNT(*) c FROM reports GROUP BY ym ORDER BY ym").fetchall()
    bycat=db.execute("SELECT category, COUNT(*) c FROM reports GROUP BY category ORDER BY c DESC").fetchall()
    status=db.execute("SELECT status, COUNT(*) c FROM reports GROUP BY status").fetchall()
    db.close()
    pack=lambda rows,k1,k2: {"labels":[r[k1] for r in rows], "data":[r[k2] for r in rows]}
    return render_template("admin/overview.html", kpis=kpis,
                           month=pack(month,"ym","c"), bycat=pack(bycat,"category","c"),
                           status=pack(status,"status","c"), title="Admin • Overview")

@app.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():
    q=(request.args.get("q") or "").strip()
    status=request.args.get("status") or ""
    category=request.args.get("category") or ""
    company_code=(request.args.get("company_code") or "").strip().upper()
    db=get_db()
    sql = """SELECT r.id,r.subject,r.status,r.category,r.created_at,c.company_code
             FROM reports r JOIN companies c ON c.id=r.company_id WHERE 1=1"""
    args=[]
    if q: sql+=" AND r.subject LIKE ?"; args.append(f"%{q}%")
    if status: sql+=" AND r.status=?"; args.append(status)
    if category: sql+=" AND r.category=?"; args.append(category)
    if company_code: sql+=" AND c.company_code=?"; args.append(company_code)
    sql+=" ORDER BY r.created_at DESC"
    rows=db.execute(sql, tuple(args)).fetchall()
    db.close()
    return render_template("admin/reports.html", rows=rows, q=q, status=status, category=category, company_code=company_code,
                           statuses=STATUSES, categories=CATEGORIES, title="Admin • Reports")

@app.route("/admin/report/<int:rid>", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_report_detail(rid):
    db=get_db()
    r=db.execute("""SELECT r.*, c.company_code FROM reports r JOIN companies c ON c.id=r.company_id WHERE r.id=?""",(rid,)).fetchone()
    if not r: db.close(); abort(404)
    if request.method=="POST":
        action=request.form.get("action")
        if action=="status":
            s=request.form.get("status") or r["status"]
            if s in STATUSES: db.execute("UPDATE reports SET status=? WHERE id=?", (s,rid))
        elif action=="assign":
            mid=request.form.get("manager_id")
            notify=(request.form.get("notify_text") or "").strip() or "You have a new item to review from Admin. Please check your messages."
            if mid:
                db.execute("UPDATE reports SET assignee_user_id=? WHERE id=?", (int(mid),rid))
                db.execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",
                           (int(mid),"New assignment",notify,now_iso()))
        elif action=="msg_public":
            body=(request.form.get("body") or "").strip()
            if body: db.execute("INSERT INTO messages(report_id,channel,sender,body,created_at,user_id) VALUES (?,?,?,?,?,?)",
                                (rid,"public","admin",body,now_iso(),session["user_id"]))
        elif action=="msg_internal":
            body=(request.form.get("body") or "").strip()
            if body: db.execute("INSERT INTO messages(report_id,channel,sender,body,created_at,user_id) VALUES (?,?,?,?,?,?)",
                                (rid,"internal","admin",body,now_iso(),session["user_id"]))
        db.commit()
    managers=db.execute("""SELECT u.id,u.email,c.company_code FROM users u
                           JOIN companies c ON c.id=u.company_id WHERE u.role='manager' ORDER BY u.email""").fetchall()
    msgs_public=db.execute("SELECT * FROM messages WHERE report_id=? AND channel='public' ORDER BY created_at",(rid,)).fetchall()
    msgs_internal=db.execute("SELECT * FROM messages WHERE report_id=? AND channel='internal' ORDER BY created_at",(rid,)).fetchall()
    db.close()
    return render_template("admin/report_detail.html", r=r, managers=managers, msgs_public=msgs_public, msgs_internal=msgs_internal,
                           statuses=STATUSES, title=f"Admin • Report {rid}")

@app.route("/admin/companies", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_companies():
    db=get_db()
    if request.method=="POST":
        delid=request.form.get("delete_id")
        if delid:
            db.execute("DELETE FROM companies WHERE id=?", (int(delid),)); db.commit()
        else:
            name=(request.form.get("name") or "").strip()
            code=(request.form.get("company_code") or "").strip().upper()
            if name and code:
                try:
                    db.execute("INSERT INTO companies(name,company_code,created_at) VALUES (?,?,?)",(name,code,now_iso()))
                    db.commit(); flash("Company created.","success")
                except sqlite3.IntegrityError:
                    flash("Company code must be unique.","danger")
    companies=db.execute("SELECT * FROM companies ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("admin/companies.html", companies=companies, title="Admin • Companies")

@app.route("/admin/managers", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_managers():
    db=get_db()
    if request.method=="POST":
        delid=request.form.get("delete_id")
        if delid:
            db.execute("DELETE FROM users WHERE id=? AND role='manager'", (int(delid),)); db.commit()
        else:
            email=(request.form.get("email") or "").strip().lower()
            pwd=request.form.get("password") or ""
            cid=int(request.form.get("company_id"))
            if email and pwd:
                from werkzeug.security import generate_password_hash
                try:
                    db.execute("INSERT INTO users(email,password_hash,role,company_id,created_at) VALUES (?,?,?,?,?)",
                               (email,generate_password_hash(pwd),"manager",cid,now_iso()))
                    db.commit(); flash("Manager created.","success")
                except sqlite3.IntegrityError:
                    flash("Email already exists.","danger")
    managers=db.execute("""SELECT u.*, c.name AS company_name, c.company_code FROM users u
                           LEFT JOIN companies c ON c.id=u.company_id
                           WHERE role='manager' ORDER BY u.created_at DESC""").fetchall()
    companies=db.execute("SELECT * FROM companies ORDER BY name").fetchall()
    db.close()
    return render_template("admin/managers.html", managers=managers, companies=companies, title="Admin • Managers")

@app.route("/admin/messages")
@login_required
@role_required("admin")
def admin_messages():
    db=get_db()
    latest=db.execute("SELECT report_id,channel,created_at,substr(body,1,120) body FROM messages ORDER BY created_at DESC LIMIT 50").fetchall()
    db.close()
    return render_template("admin/messages.html", latest=latest, title="Admin • Messages")

@app.route("/admin/notifications")
@login_required
@role_required("admin")
def admin_notifications():
    db=get_db()
    notes=db.execute("""SELECT n.*, u.email FROM notifications n JOIN users u ON u.id=n.user_id
                        ORDER BY n.created_at DESC LIMIT 100""").fetchall()
    db.close()
    return render_template("admin/notifications.html", notes=notes, title="Admin • Notifications")

@app.route("/admin/media", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_media():
    if request.method=="POST":
        f=request.files.get("file")
        if f and f.filename:
            path=os.path.join(MEDIA_DIR, f.filename)
            f.save(path); flash("Uploaded.","success")
    files=[f for f in os.listdir(MEDIA_DIR) if not f.startswith(".")]
    return render_template("admin/media.html", files=files, title="Admin • Media")

@app.route("/admin/content", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_content():
    db=get_db()
    if request.method=="POST":
        for key in ["home_intro","how_long","benefits","who_help"]:
            val=request.form.get(key) or ""
            db.execute("INSERT INTO content_blocks(key,body,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at",
                       (key,val,now_iso()))
        db.commit(); flash("Saved content.","success")
    rows=db.execute("SELECT key,body FROM content_blocks").fetchall()
    blocks={r["key"]:r["body"] for r in rows}
    db.close()
    return render_template("admin/content.html", blocks=blocks, title="Admin • Content")

@app.route("/admin/settings", methods=["GET","POST"])
@login_required
@role_required("admin")
def admin_settings():
    db=get_db()
    if request.method=="POST":
        fields=["smtp_host","smtp_port","smtp_user","smtp_pass","stripe_pk","stripe_sk","paypal_id","paypal_secret","sso_google","sso_ms"]
        for k in fields:
            v=request.form.get(k) or ""
            db.execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                       (k,v,now_iso()))
        db.commit(); flash("Saved settings.","success")
    s={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings")}
    db.close()
    class Dot: pass
    dot=Dot(); [setattr(dot,k,v) for k,v in s.items()]
    return render_template("admin/settings.html", s=dot, title="Admin • Settings")

# --------------------- manager ---------------------
@app.route("/manager")
@login_required
@role_required("manager")
def manager_overview():
    cid=session.get("company_id")
    db=get_db()
    k=db.execute("""SELECT
      SUM(CASE WHEN status='new' THEN 1 ELSE 0 END),
      SUM(CASE WHEN status IN('in_review','awaiting_info') THEN 1 ELSE 0 END),
      SUM(CASE WHEN status IN('resolved','closed') THEN 1 ELSE 0 END)
    FROM reports WHERE company_id=?""",(cid,)).fetchone()
    kpis={"new":k[0] or 0,"inproc":k[1] or 0,"closed":k[2] or 0}
    month=db.execute("SELECT substr(created_at,1,7) ym, COUNT(*) c FROM reports WHERE company_id=? GROUP BY ym ORDER BY ym",(cid,)).fetchall()
    bycat=db.execute("SELECT category, COUNT(*) c FROM reports WHERE company_id=? GROUP BY category ORDER BY c DESC",(cid,)).fetchall()
    db.close()
    pack=lambda rows,k1,k2: {"labels":[r[k1] for r in rows], "data":[r[k2] for r in rows]}
    return render_template("manager_overview.html", kpis=kpis, month=pack(month,"ym","c"), bycat=pack(bycat,"category","c"), title="Manager • Overview")

@app.route("/manager/reports")
@login_required
@role_required("manager")
def manager_reports():
    cid=session.get("company_id")
    db=get_db()
    rows=db.execute("""SELECT id,subject,category,status,created_at FROM reports WHERE company_id=? ORDER BY created_at DESC""",(cid,)).fetchall()
    db.close()
    return render_template("manager_reports.html", rows=rows, title="Manager • Reports")

@app.route("/manager/messages", methods=["GET","POST"])
@login_required
@role_required("manager")
def manager_messages():
    uid=session["user_id"]
    cid=session["company_id"]
    db=get_db()
    # Show internal messages for reports assigned to this manager
    msgs=db.execute("""SELECT m.* FROM messages m
                       JOIN reports r ON r.id=m.report_id
                       WHERE m.channel='internal' AND r.assignee_user_id=?
                       ORDER BY m.created_at DESC LIMIT 200""",(uid,)).fetchall()
    if request.method=="POST":
        body=(request.form.get("body") or "").strip()
        if body:
            # Post to the most recent assigned report (or ignore if none)
            r=db.execute("SELECT id FROM reports WHERE assignee_user_id=? ORDER BY created_at DESC LIMIT 1",(uid,)).fetchone()
            if r:
                db.execute("INSERT INTO messages(report_id,channel,sender,body,created_at,user_id) VALUES (?,?,?,?,?,?)",
                           (r["id"],"internal","manager",body,now_iso(),uid))
                # notify admin(s) – optional: omitted here
                db.commit(); flash("Sent to admin.","success")
        return redirect(url_for("manager_messages"))
    db.close()
    return render_template("manager_messages.html", msgs=msgs, title="Manager • Messages")

@app.route("/manager/notifications")
@login_required
@role_required("manager")
def manager_notifications():
    uid=session["user_id"]; db=get_db()
    notes=db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC",(uid,)).fetchall()
    db.close()
    return render_template("manager_notifications.html", notes=notes, title="Manager • Notifications")

# --------------------- misc ---------------------
@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, message="Forbidden"), 403
@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, message="Not Found"), 404

if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
