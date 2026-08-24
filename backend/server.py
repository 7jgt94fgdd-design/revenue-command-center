import sqlite3, hashlib, secrets, json, os, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from pathlib import Path

BASE=Path(__file__).resolve().parent
DB=BASE/"rcm.sqlite3"
sessions={}

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

def hashpw(p,s=None):
    s=s or secrets.token_hex(16)
    return s, hashlib.sha256((s+p).encode()).hexdigest()

def init():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY,name TEXT NOT NULL,plan TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,salt TEXT NOT NULL,role TEXT NOT NULL,organization_id TEXT NOT NULL REFERENCES organizations(id));
    CREATE TABLE IF NOT EXISTS claims(id TEXT,organization_id TEXT NOT NULL, payer TEXT, amount REAL, status TEXT, category TEXT, priority TEXT, deadline TEXT, owner TEXT, PRIMARY KEY(id,organization_id));
    CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,organization_id TEXT,user_id INTEGER,action TEXT,resource TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS work_items(id INTEGER PRIMARY KEY AUTOINCREMENT,organization_id TEXT NOT NULL,claim_id TEXT NOT NULL,assigned_to TEXT,status TEXT NOT NULL DEFAULT 'Open',due_date TEXT,notes TEXT,created_at TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS claim_events(id INTEGER PRIMARY KEY AUTOINCREMENT,organization_id TEXT NOT NULL,claim_id TEXT NOT NULL,user_id INTEGER,action TEXT,from_status TEXT,to_status TEXT,note TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY AUTOINCREMENT,organization_id TEXT NOT NULL,claim_id TEXT NOT NULL,user_id INTEGER,filename TEXT NOT NULL,content_type TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT);
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,organization_id TEXT NOT NULL,user_id INTEGER,title TEXT NOT NULL,message TEXT NOT NULL,kind TEXT NOT NULL,read INTEGER NOT NULL DEFAULT 0,created_at TEXT);
    """)
    if c.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]==0:
        c.executemany("INSERT INTO organizations VALUES(?,?,?)",[
            ("gmh-demo","Guam Memorial Hospital - RCM Demo","Enterprise"),
            ("island-demo","Island Specialty Clinic -RCM Demo","Growth"),
            ("pacific-demo","Pacific Family Practice - RCM Demo","Clinic")])
        for email,pw,role,org in [
            ("admin@demo.local","ChangeMe123!","Owner","gmh-demo"),
            ("manager@demo.local","Manager123!","RCM Manager","gmh-demo")]:
            s,h=hashpw(pw)
            c.execute("INSERT INTO users(email,password_hash,salt,role,organization_id) VALUES(?,?,?,?,?)",(email,h,s,role,org))
        claims=[
        ("10802","gmh-demo","Pacific Care",31000,"Denied","Medical Necessity","High","2026-09-03","Ana Reyes"),
        ("10601","gmh-demo","Pacific Care",22500,"Denied","Medical Necessity","High","2026-09-01","Ana Reyes"),
        ("10482","gmh-demo","Example Health Plan",18420,"Denied","Medical Necessity","High","2026-09-05","Maria Santos"),
        ("10501","gmh-demo","Island Health Plan",11200,"Denied","Authorization","High","2026-08-31","James Cruz"),
        ("10519","gmh-demo","Pacific Care",9800,"Denied","Coding","High","2026-08-29","Maria Santos"),
        ("10672","gmh-demo","Pacific Care",14700,"Denied","Documentation","Medium","2026-09-12","Ana Reyes"),
        ("10704","gmh-demo","Example Health Plan",6800,"Pending","Timely Filing Risk","High","2026-08-30","Maria Santos")]
        c.executemany("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?)",claims)
    c.commit(); c.close()
    
def init():
    ...
    c.commit()
    c.close()
    
def log_claim_event(c, org, claim_id,user_id, action, from_status, to_status, note=""):
    
    c.execute(
        """
        INSERT INTO claim_events(
            organization_id,
            claim_id,
            user_id,
            action,
            from_status,
            to_status,
            note,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            org,
            claim_id,
            user_id,
            action,
            from_status,
            to_status,
            note,
            datetime.datetime.utcnow().isoformat()
        )
    )
    
def user_for(h):
    token=h.headers.get("Authorization","").replace("Bearer ","")
    uid=sessions.get(token)
    if not uid:return None
    c=db(); u=c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone(); c.close()
    return u

class Handler(BaseHTTPRequestHandler):
    def sendj(self,code,obj):
        b=json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        n=int(self.headers.get("Content-Length","0")); return json.loads(self.rfile.read(n) or b"{}")
    def do_POST(self):
        p=urlparse(self.path).path
        if p=="/api/login":
            x=self.body(); c=db(); u=c.execute("SELECT * FROM users WHERE email=?",(x.get("email",""),)).fetchone()
            if not u:
                c.close(); return self.sendj(401,{"error":"Invalid credentials"})
            _,hh=hashpw(x.get("password",""),u["salt"])
            if hh!=u["password_hash"]:
                c.close(); return self.sendj(401,{"error":"Invalid credentials"})
            token=secrets.token_urlsafe(32); sessions[token]=u["id"]
            c.execute("INSERT INTO audit_events(organization_id,user_id,action,resource,created_at) VALUES(?,?,?,?,?)",(u["organization_id"],u["id"],"login","session",datetime.datetime.utcnow().isoformat()))
            c.commit(); c.close()
            return self.sendj(200,{"token":token,"user":{"id":u["id"],"email":u["email"],"role":u["role"],"organization_id":u["organization_id"]}})
        if p.startswith("/api/claims/") and p.endswith("/action"):
            u=user_for(self)
            if not u:return self.sendj(401,{"error":"Authentication required"})
            claim_id=p.split("/")[3]; x=self.body(); action=x.get("action")
            allowed={"assign","status","appeal","note"}
            if action not in allowed:return self.sendj(400,{"error":"Unsupported action"})
            c=db(); org=u["organization_id"]
            claim=c.execute("SELECT * FROM claims WHERE id=? AND organization_id=?",(claim_id,org)).fetchone()
            if not claim:c.close(); return self.sendj(404,{"error":"Claim not found"})
            frm=claim["status"]; to=frm
            if action=="status":
                to=x.get("status")
                if to not in {"Pending","Denied","Appeal Prepared","Appealed","Resolved"}:
                    c.close(); return self.sendj(400,{"error":"Invalid status"})
                c.execute("UPDATE claims SET status=? WHERE id=? AND organization_id=?",(to,claim_id,org))
            elif action=="assign":
                owner=x.get("owner","")
                if not owner:c.close(); return self.sendj(400,{"error":"Owner required"})
                c.execute("UPDATE claims SET owner=? WHERE id=? AND organization_id=?",(owner,claim_id,org))
            elif action=="appeal":
                to="Appeal Prepared"
                c.execute("UPDATE claims SET status=? WHERE id=? AND organization_id=?",(to,claim_id,org))
                c.execute("INSERT INTO work_items(organization_id,claim_id,assigned_to,status,due_date,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                          (org,claim_id,x.get("owner") or claim["owner"],"Appeal Draft","",x.get("note",""),datetime.datetime.utcnow().isoformat(),datetime.datetime.utcnow().isoformat()))
            elif action=="note":
                c.execute("INSERT INTO work_items(organization_id,claim_id,assigned_to,status,due_date,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                          (org,claim_id,u["email"],"Note","",""+x.get("note",""),datetime.datetime.utcnow().isoformat(),datetime.datetime.utcnow().isoformat()))
            log_claim_event(c,org,claim_id,u["id"],action,frm,to,x.get("note",""))
            c.commit(); c.close()
            return self.sendj(200,{"ok":True,"claim_id":claim_id,"status":to})
        if p.startswith("/api/claims/") and p.endswith("/documents"):
            u=user_for(self)
            if not u:return self.sendj(401,{"error":"Authentication required"})
            claim_id=p.split("/")[3]; x=self.body(); c=db(); org=u["organization_id"]
            claim=c.execute("SELECT id FROM claims WHERE id=? AND organization_id=?",(claim_id,org)).fetchone()
            if not claim:c.close(); return self.sendj(404,{"error":"Claim not found"})
            filename=x.get("filename","attachment.txt").strip()
            content=x.get("content","")
            if not content or len(content)>200000:c.close(); return self.sendj(400,{"error":"Document content required and must be under 200KB"})
            c.execute("INSERT INTO documents(organization_id,claim_id,user_id,filename,content_type,content,created_at) VALUES(?,?,?,?,?,?,?)",
                      (org,claim_id,u["id"],filename,x.get("content_type","text/plain"),content,datetime.datetime.utcnow().isoformat()))
            c.execute("INSERT INTO audit_events(organization_id,user_id,action,resource,created_at) VALUES(?,?,?,?,?)",
                      (org,u["id"],"document_uploaded","claim:"+claim_id,datetime.datetime.utcnow().isoformat()))
            c.commit(); c.close(); return self.sendj(201,{"ok":True,"claim_id":claim_id,"filename":filename})
        if p=="/api/notifications/read":
            u=user_for(self)
            if not u:return self.sendj(401,{"error":"Authentication required"})
            x=self.body(); c=db(); c.execute("UPDATE notifications SET read=1 WHERE id=? AND organization_id=? AND user_id=?",(x.get("id"),u["organization_id"],u["id"])); c.commit(); c.close()
            return self.sendj(200,{"ok":True})
        if p=="/api/logout":
            t=self.headers.get("Authorization","").replace("Bearer ",""); sessions.pop(t,None); return self.sendj(200,{"ok":True})
        return self.sendj(404,{"error":"Not found"})
    def do_GET(self):
        p=urlparse(self.path).path
        u=user_for(self)
        if p=="/api/health": return self.sendj(200,{"ok":True})
        if not u:return self.sendj(401,{"error":"Authentication required"})
        c=db(); org=u["organization_id"]
        if p=="/api/me":
            out={"user":{"id":u["id"],"email":u["email"],"role":u["role"],"organization_id":org}}
        elif p=="/api/organizations":
            # Platform-level listing is restricted to Owner in this demo.
            if u["role"]!="Owner": c.close(); return self.sendj(403,{"error":"Owner role required"})
            out={"organizations":[dict(x) for x in c.execute("SELECT * FROM organizations").fetchall()]}
        elif p=="/api/dashboard":
            r=c.execute("SELECT COUNT(*) n,COALESCE(SUM(amount),0) amount FROM claims WHERE organization_id=?",(org,)).fetchone()
            d=c.execute("SELECT COUNT(*) n,COALESCE(SUM(amount),0) amount FROM claims WHERE organization_id=? AND status='Denied'",(org,)).fetchone()
            # Generate demo deadline alerts for claims due within 7 days.
            now=datetime.datetime.utcnow()
            upcoming=[]
            for cr in c.execute("SELECT id,deadline,amount,owner FROM claims WHERE organization_id=?",(org,)).fetchall():
                try:
                    days=(datetime.datetime.fromisoformat(cr["deadline"])-now).days
                    if days <= 7:
                        upcoming.append((cr,days))
                except Exception: pass
            for cr,days in upcoming:
                msg=f"Claim #{cr['id']} is due {cr['deadline']} ({max(days,0)} days remaining) — ${cr['amount']:,.0f}."
                exists=c.execute("SELECT id FROM notifications WHERE organization_id=? AND title=? AND created_at>?",(org,f"Deadline alert #{cr['id']}",(now-datetime.timedelta(hours=24)).isoformat())).fetchone()
                if not exists:
                    c.execute("INSERT INTO notifications(organization_id,user_id,title,message,kind,created_at) VALUES(?,?,?,?,?,?)",
                              (org,u["id"],f"Deadline alert #{cr['id']}",msg,"deadline",now.isoformat()))
            c.commit()
            out={"organization_id":org,"claims":r["n"],"open_value":r["amount"],"denied_value":d["amount"],"opportunity":round(d["amount"]*.22,2),"deadline_alerts":len(upcoming)}
        elif p=="/api/claims":
            rows=c.execute("SELECT * FROM claims WHERE organization_id=? ORDER BY CASE priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, amount DESC",(org,)).fetchall()
            out={"claims":[dict(x) for x in rows]}
        elif p=="/api/work-items":
            rows=c.execute("SELECT * FROM work_items WHERE organization_id=? ORDER BY id DESC",(org,)).fetchall()
            out={"work_items":[dict(x) for x in rows]}
        elif p.startswith("/api/claims/") and p.endswith("/events"):
            claim_id=p.split("/")[3]
            rows=c.execute("SELECT * FROM claim_events WHERE organization_id=? AND claim_id=? ORDER BY id DESC",(org,claim_id)).fetchall()
            out={"events":[dict(x) for x in rows]}
        elif p=="/api/documents":
            rows=c.execute("SELECT id,organization_id,claim_id,user_id,filename,content_type,created_at FROM documents WHERE organization_id=? ORDER BY id DESC",(org,)).fetchall()
            out={"documents":[dict(x) for x in rows]}
        elif p=="/api/notifications":
            rows=c.execute("SELECT * FROM notifications WHERE organization_id=? AND (user_id=? OR user_id IS NULL) ORDER BY id DESC LIMIT 100",(org,u["id"])).fetchall()
            out={"notifications":[dict(x) for x in rows]}
        elif p.startswith("/api/claims/") and p.endswith("/documents"):
            claim_id=p.split("/")[3]
            rows=c.execute("SELECT id,organization_id,claim_id,user_id,filename,content_type,created_at FROM documents WHERE organization_id=? AND claim_id=? ORDER BY id DESC",(org,claim_id)).fetchall()
            out={"documents":[dict(x) for x in rows]}
        elif p=="/api/audit":
            rows=c.execute("SELECT * FROM audit_events WHERE organization_id=? ORDER BY id DESC LIMIT 100",(org,)).fetchall()
            out={"events":[dict(x) for x in rows]}
        else:c.close(); return self.sendj(404,{"error":"Not found"})
        c.close(); self.sendj(200,out)

if __name__=="__main__":

    init()

    port = int(os.environ.get("PORT", "8080"))

    print(f"Revenue Command Center API running on port {port}")

    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()