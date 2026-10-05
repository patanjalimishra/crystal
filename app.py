import os, re, sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-before-deployment-" + os.urandom(16).hex())
DB = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "screener.db"))

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, requirements TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY, role_id INTEGER NOT NULL, name TEXT NOT NULL, email TEXT DEFAULT '', resume TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE);
    """)
    conn.commit(); conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("user_id"): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def analyze_resume(resume):
    """Deterministic, explainable checks. Flags are review signals, never proof of dishonesty."""
    text = resume or ""
    low = text.lower()
    flags = []
    injection_patterns = [
        r"ignore (all )?(previous|prior|above) instructions",
        r"disregard (all )?(previous|prior|above) instructions",
        r"rank this candidate (first|highest)",
        r"give (this candidate|me) (a )?(perfect|100|maximum) score",
        r"system prompt", r"you are now (an? )?(ai|assistant|recruiter)",
        r"do not tell the recruiter", r"override (the )?(scoring|instructions)"
    ]
    hits = [p for p in injection_patterns if re.search(p, low)]
    if hits:
        flags.append({"type":"Possible prompt injection","severity":"high",
          "evidence":"The resume contains language that appears to instruct an AI or influence its ranking.",
          "why":"Resume content must be treated as untrusted evidence, not as instructions. The matching text is isolated from scoring.",
          "action":"Review the quoted text and continue only using job-relevant evidence."})

    # Parse common month/year and year-only employment ranges.
    months = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    date = rf"(?:{months}\s+)?(?:19|20)\d{{2}}"
    ranges = re.findall(rf"({date})\s*(?:-|–|—|to)\s*({date}|present|current|now)", text, re.I)
    def month_num(s):
        s=s.strip().lower()
        m=re.search(r"(19|20)\d{2}", s)
        if not m: return None
        year=int(m.group())
        mm=re.search(r"[a-z]+",s)
        mon=1
        if mm:
            names=["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]
            key=mm.group()[:3]
            if key in names: mon=names.index(key)+1
        return year*12+mon
    jobs=[]
    for start,end in ranges:
        a=month_num(start); b=month_num(end) if end.lower() not in ("present","current","now") else datetime.now().year*12+datetime.now().month
        if a and b and b<a:
            flags.append({"type":"Reversed employment dates","severity":"medium","evidence":f"Employment range “{start} – {end}” appears to end before it starts.",
             "why":"The dates may be a typo, formatting issue, or genuine timeline conflict.","action":"Ask the candidate to confirm the dates; do not infer intent."})
        elif a and b: jobs.append((a,b,start,end))
    for i,(a,b,s,e) in enumerate(jobs):
        for c,d,s2,e2 in jobs[i+1:]:
            if max(a,c) < min(b,d) and (s != s2 or e != e2):
                # only flag one overlapping pair; overlapping roles can be legitimate
                flags.append({"type":"Potential employment overlap","severity":"medium","evidence":f"Date ranges “{s} – {e}” and “{s2} – {e2}” overlap.",
                 "why":"Concurrent roles can be valid (for example consulting or part-time work), but the resume does not explain the overlap.","action":"Clarify whether the roles were concurrent, part-time, contract, or incorrectly dated."})
                break
        if any(f["type"]=="Potential employment overlap" for f in flags): break

    # Repeated quantified vement language across resume bullets/lines.
    lines=[x.strip(" •-\t") for x in text.splitlines() if x.strip()]
    quant=[]
    for line in lines:
        if re.search(r"\b(?:improv(?:ed|ement)|increas(?:ed|e)|reduc(?:ed|tion)|boost(?:ed)?|optimis(?:ed|ed)|optim(?:ized|ised))\b",line,re.I) and re.search(r"\b\d+\s*%",line):
            quant.append(line)
    normalized=[]
    for line in quant:
        # Compare normalized templates while retaining the underlying original lines for evidence.
        n=re.sub(r"\b\d+\s*%", "<PERCENT>", line.lower())
        n=re.sub(r"\b(at|for|in|by|across)\s+[\w.-]+", r"\1 <ORG>", n)
        n=re.sub(r"[^a-z<> ]"," ",n)
        normalized.append((line,re.sub(r"\s+"," ",n).strip()))
    pairs=[]
    for i in range(len(normalized)):
        for j in range(i+1,len(normalized)):
            a=normalized[i][1].split(); b=normalized[j][1].split()
            if not a or not b: continue
            overlap=len(set(a)&set(b))/max(1,len(set(a)|set(b)))
            if overlap >= .62: pairs.append((normalized[i][0],normalized[j][0]))
    if len(quant)>=3 and pairs:
        first,second=pairs[0]
        flags.append({"type":"Repeated quantified achievement template","severity":"low","evidence":f"Similar percentage-based achievement wording appears across multiple bullets. Examples: “{first[:180]}” / “{second[:180]}”.",
          "why":"Repeated wording may reflect a template or generic phrasing; it does not establish that a claim is false.","action":"Ask for context, baseline, measurement method, and the candidate’s specific contribution."})

    return flags

def score_resume(resume, role):
    reqs=[x.strip() for x in (role["requirements"] or "").splitlines() if x.strip()]
    text=(resume or "").lower()
    matched=[r for r in reqs if any(term in text for term in re.findall(r"[a-zA-Z0-9+#.]+",r.lower()) if len(term)>1)]
    score=round(100*len(matched)/len(reqs)) if reqs else 0
    # Role-description keywords are contextual signals, not a semantic model.
    return score, matched, [r for r in reqs if r not in matched]

@app.route("/")
def index():
    if not session.get("user_id"): return redirect(url_for("login"))
    roles=db().execute("SELECT r.*, (SELECT COUNT(*) FROM candidates c WHERE c.role_id=r.id) AS candidate_count FROM roles r WHERE user_id=? ORDER BY id DESC",(session["user_id"],)).fetchall()
    return render_template("index.html", roles=roles)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        if not email or len(password)<10:
            flash("Enter an email and a password of at least 10 characters.","error")
        else:
            try:
                cur=db().execute("INSERT INTO users(email,password_hash) VALUES (?,?)",(email,generate_password_hash(password)))
                db().commit(); session["user_id"]=cur.lastrowid; session["email"]=email
                return redirect(url_for("index"))
            except sqlite3.IntegrityError: flash("An account with that email already exists.","error")
    return render_template("auth.html", mode="Create account")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower()
        user=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if user and check_password_hash(user["password_hash"],request.form.get("password","")):
            session.clear(); session["user_id"]=user["id"]; session["email"]=user["email"]
            return redirect(url_for("index"))
        flash("Email or password was not recognised.","error")
    return render_template("auth.html", mode="Welcome back")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/roles/new", methods=["GET","POST"])
@login_required
def new_role():
    if request.method=="POST":
        title=request.form.get("title","").strip(); desc=request.form.get("description","").strip(); reqs=request.form.get("requirements","").strip()
        if not title or not desc or not reqs: flash("Complete all fields, including at least one requirement.","error")
        else:
            db().execute("INSERT INTO roles(user_id,title,description,requirements) VALUES (?,?,?,?)",(session["user_id"],title,desc,reqs)); db().commit()
            flash("Role created.","success"); return redirect(url_for("index"))
    return render_template("role_form.html")

def owned_role(role_id):
    return db().execute("SELECT * FROM roles WHERE id=? AND user_id=?",(role_id,session["user_id"])).fetchone()

@app.route("/roles/<int:role_id>")
@login_required
def role_detail(role_id):
    role=owned_role(role_id)
    if not role: return "Role not found",404
    candidates=db().execute("SELECT * FROM candidates WHERE role_id=? ORDER BY id DESC",(role_id,)).fetchall()
    rows=[]
    for c in candidates:
        flags=analyze_resume(c["resume"]); score,matched,missing=score_resume(c["resume"],role)
        rows.append({"candidate":c,"flags":flags,"score":score,"matched":matched,"missing":missing})
    rows.sort(key=lambda x:(-x["score"],len(x["flags"])))
    return render_template("role_detail.html",role=role,rows=rows)

@app.route("/roles/<int:role_id>/candidates/new", methods=["GET","POST"])
@login_required
def new_candidate(role_id):
    role=owned_role(role_id)
    if not role: return "Role not found",404
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip(); resume=request.form.get("resume","").strip()
        if not name or len(resume)<40: flash("Add a candidate name and resume text (at least 40 characters).","error")
        else:
            db().execute("INSERT INTO candidates(role_id,name,email,resume) VALUES (?,?,?,?)",(role_id,name,email,resume)); db().commit()
            flash("Candidate added and integrity checks completed.","success")
            return redirect(url_for("candidate_detail",role_id=role_id,candidate_id=db().execute("SELECT last_insert_rowid()").fetchone()[0]))
    return render_template("candidate_form.html",role=role)

@app.route("/roles/<int:role_id>/candidates/<int:candidate_id>")
@login_required
def candidate_detail(role_id,candidate_id):
    role=owned_role(role_id)
    if not role: return "Role not found",404
    c=db().execute("SELECT * FROM candidates WHERE id=? AND role_id=?",(candidate_id,role_id)).fetchone()
    if not c:return "Candidate not found",404
    flags=analyze_resume(c["resume"]); score,matched,missing=score_resume(c["resume"],role)
    return render_template("candidate_detail.html",role=role,c=c,flags=flags,score=score,matched=matched,missing=missing)

@app.route("/roles/<int:role_id>/compare",methods=["POST"])
@login_required
def compare(role_id):
    role=owned_role(role_id)
    if not role:return "Role not found",404
    ids=[request.form.get("candidate_a"),request.form.get("candidate_b")]
    cs=[db().execute("SELECT * FROM candidates WHERE id=? AND role_id=?",(x,role_id)).fetchone() for x in ids]
    if not all(cs): flash("Choose two candidates to compare.","error"); return redirect(url_for("role_detail",role_id=role_id))
    analyses=[]
    for c in cs:
        score,matched,missing=score_resume(c["resume"],role); analyses.append((c,score,matched,missing))
    return render_template("compare.html",role=role,analyses=analyses)

@app.errorhandler(500)
def server_error(e):
    app.logger.exception(e)
    return "Something went wrong. Please try again. No candidate has been silently discarded.",500

if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)

init_db()
