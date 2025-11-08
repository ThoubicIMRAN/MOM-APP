# app.py
import streamlit as st
import sqlite3
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import date, timedelta, datetime
import json
import requests
from fpdf import FPDF
from urllib.parse import urlencode

# ----------------------------
# CONFIG - EDIT THESE VALUES
# ----------------------------
ADMIN_USERNAME = "admin"                      # admin username
ADMIN_EMAIL = "you_admin@example.com"         # admin email (receives approvals / password reset requests)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "you_admin@example.com"          # same as ADMIN_EMAIL typically
SMTP_PASSWORD = "YOUR_SMTP_APP_PASSWORD"      # Use app password, don't commit to VCS
TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/..."  # Replace with your Teams Incoming Webhook
APP_BASE_URL = "https://your-app-deploy-url"  # Replace with your deployed Streamlit app URL (for deep links)
DB_PATH = "mom_collab.db"
# ----------------------------

st.set_page_config(page_title="MoM Collaboration Platform", layout="wide")

# ----------------------------
# DB Setup
# ----------------------------
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

# Users table: username (PK), password_hash, email, approved (0/1), role ('admin'/'user')
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    email TEXT,
    approved INTEGER,
    role TEXT
)
""")

# Projects table
c.execute("""
CREATE TABLE IF NOT EXISTS projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT,
    description TEXT,
    created_by TEXT,
    created_at TEXT
)
""")

# Project shares (which users can view the project)
c.execute("""
CREATE TABLE IF NOT EXISTS project_shares (
    project_id INTEGER,
    username TEXT
)
""")

# MoM records
c.execute("""
CREATE TABLE IF NOT EXISTS mom_records (
    mom_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    title TEXT,
    description TEXT,
    participants TEXT,
    meeting_date TEXT,
    created_by TEXT,
    created_at TEXT,
    pdf_path TEXT
)
""")

# Tasks table (per Mom)
c.execute("""
CREATE TABLE IF NOT EXISTS tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    mom_id INTEGER,
    title TEXT,
    description TEXT,
    assignee TEXT,
    reporter TEXT,
    due_date TEXT,
    status TEXT,
    assignee_notes TEXT,
    updated_at TEXT
)
""")

conn.commit()

# ----------------------------
# Utilities
# ----------------------------
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def send_email(to_address: str, subject: str, body: str):
    """Sends an email via configured SMTP server. Expect SMTP config to be correct."""
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_EMAIL
        msg["To"] = to_address
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        st.warning(f"Email send failed: {e}")

def send_teams_message(text: str):
    """Post a simple text payload to Teams incoming webhook."""
    try:
        payload = {"text": text}
        requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=8)
    except Exception as e:
        st.warning(f"Teams post failed: {e}")

def current_ts():
    return datetime.utcnow().isoformat()

def create_deep_link(mom_id:int, task_id:int):
    params = urlencode({"mom_id": mom_id, "task_id": task_id})
    return f"{APP_BASE_URL}/?{params}"

def generate_pdf_for_mom(mom_id:int, out_path="mom_export.pdf"):
    """Creates a simple PDF export for a MoM and returns path."""
    c.execute("SELECT title, description, participants, meeting_date, created_by FROM mom_records WHERE mom_id=?", (mom_id,))
    mom = c.fetchone()
    if not mom:
        return None
    title, description, participants, meeting_date, created_by = mom
    c.execute("SELECT title, description, assignee, reporter, due_date, status, assignee_notes FROM tasks WHERE mom_id=?", (mom_id,))
    tasks = c.fetchall()

    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Minutes of Meeting", ln=True, align="C")
    pdf.ln(6)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 8, "Title:")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, title)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 8, "Meeting Date:")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, meeting_date, ln=True)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 8, "Description:")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, description)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 8, "Participants:")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, participants)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 8, "Tasks", ln=True)
    pdf.ln(4)
    pdf.set_font("Arial", "", 11)
    for idx, t in enumerate(tasks, start=1):
        t_title, t_desc, assignee, reporter, due_date, status, notes = t
        pdf.multi_cell(0, 7, f"{idx}. {t_title} (Status: {status})")
        pdf.multi_cell(0, 7, f"   Description: {t_desc}")
        pdf.multi_cell(0, 7, f"   Assignee: {assignee} | Reporter: {reporter} | Due: {due_date}")
        pdf.multi_cell(0, 7, f"   Assignee Notes: {notes or '-'}")
        pdf.ln(2)

    pdf.output(out_path)
    return out_path

# ----------------------------
# Authentication / Session helpers
# ----------------------------
def register_user(username, password, email):
    try:
        pw_hash = hash_password(password)
        c.execute("INSERT INTO users (username, password_hash, email, approved, role) VALUES (?, ?, ?, ?, ?)",
                  (username, pw_hash, email, 0, "user"))
        conn.commit()
        # notify admin for approval
        send_email(ADMIN_EMAIL,
                   "New MoM App Registration Request",
                   f"User '{username}' ({email}) registered and awaits approval.")
        return True, "Registration submitted — admin will approve."
    except sqlite3.IntegrityError:
        return False, "Username already exists."

def check_login(username, password):
    pw_hash = hash_password(password)
    c.execute("SELECT username, approved, role FROM users WHERE username=? AND password_hash=?", (username, pw_hash))
    row = c.fetchone()
    if not row:
        # maybe admin special-case
        if username == ADMIN_USERNAME and password == ADMIN_USERNAME:
            # default admin login fallback (only if not stored) — encourage to create admin user
            return ADMIN_USERNAME, 1, "admin"
        return None
    return row  # (username, approved, role)

def get_pending_users():
    c.execute("SELECT username, email FROM users WHERE approved=0")
    return c.fetchall()

def approve_user(username):
    c.execute("UPDATE users SET approved=1 WHERE username=?", (username,))
    conn.commit()
    # send approval email to user if email exists
    c.execute("SELECT email FROM users WHERE username=?", (username,))
    r = c.fetchone()
    if r and r[0]:
        send_email(r[0], "Your MoM app account was approved", f"Hello {username},\n\nYour account has been approved by the admin.")
    return True

def request_password_reset(username):
    # email admin to handle reset
    c.execute("SELECT email FROM users WHERE username=?", (username,))
    row = c.fetchone()
    send_email(ADMIN_EMAIL, "Password Reset Request",
               f"User '{username}' requested a password reset. Their email: {row[0] if row else 'unknown'}. Please assist.")
    return True

# ----------------------------
# UI: Login/Register
# ----------------------------
def login_register_ui():
    st.title("🔐 MoM Collaboration — Login / Register")

    if "auth" not in st.session_state:
        st.session_state.auth = False

    col1, col2 = st.columns([1,1])
    with col1:
        st.subheader("Login")
        login_user = st.text_input("Username", key="login_user")
        login_pw = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login"):
            row = check_login(login_user, login_pw)
            if row:
                username, approved, role = row
                if approved == 1 or username == ADMIN_USERNAME:
                    st.session_state.auth = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.success(f"Logged in as {username} ({role})")
                    st.experimental_rerun()
                else:
                    st.warning("Your account is pending admin approval.")
            else:
                st.error("Invalid credentials.")
    with col2:
        st.subheader("Register (request access)")
        reg_user = st.text_input("Choose username", key="reg_user")
        reg_pw = st.text_input("Choose password", type="password", key="reg_pw")
        reg_email = st.text_input("Email", key="reg_email")
        if st.button("Register"):
            ok, msg = register_user(reg_user, reg_pw, reg_email)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    st.markdown("---")
    st.subheader("Forgot Password")
    fr_user = st.text_input("Enter username to request password reset", key="fr_user")
    if st.button("Send reset request"):
        if fr_user:
            request_password_reset(fr_user)
            st.info("Password reset request sent to admin.")

# ----------------------------
# Admin Dashboard
# ----------------------------
def admin_dashboard():
    st.title("👑 Admin Dashboard")
    st.sidebar.write(f"Signed in as: **{st.session_state.username}** (admin)")

    # Admin panels
    tabs = st.tabs(["Users & Approvals", "Projects & Sharing", "Create MoM", "All MoMs", "Settings"])
    # ---------- Users & Approvals ----------
    with tabs[0]:
        st.header("User Approvals & Management")
        pending = get_pending_users()
        if pending:
            for u, email in pending:
                cols = st.columns([4,2,2])
                cols[0].write(f"**{u}** — {email}")
                if cols[1].button(f"Approve##{u}"):
                    approve_user(u)
                    st.success(f"{u} approved.")
                    st.experimental_rerun()
                if cols[2].button(f"Reject##{u}"):
                    c.execute("DELETE FROM users WHERE username=?", (u,))
                    conn.commit()
                    st.info(f"{u} removed.")
                    st.experimental_rerun()
        else:
            st.info("No pending users.")

        st.markdown("---")
        st.subheader("Create Admin / User Manually")
        manu_user = st.text_input("Username (create)", key="manu_user")
        manu_pw = st.text_input("Password", key="manu_pw", type="password")
        manu_email = st.text_input("Email", key="manu_email")
        manu_role = st.selectbox("Role", ["user", "admin"], key="manu_role")
        if st.button("Create user"):
            try:
                c.execute("INSERT INTO users (username, password_hash, email, approved, role) VALUES (?, ?, ?, ?, ?)",
                          (manu_user, hash_password(manu_pw), manu_email, 1, manu_role))
                conn.commit()
                st.success("User created.")
            except Exception as e:
                st.error(f"Create failed: {e}")

    # ---------- Projects & Sharing ----------
    with tabs[1]:
        st.header("Projects & Sharing")
        st.subheader("Create Project")
        pname = st.text_input("Project name", key="pname")
        pdesc = st.text_area("Project description", key="pdesc")
        if st.button("Create project"):
            c.execute("INSERT INTO projects (project_name, description, created_by, created_at) VALUES (?, ?, ?, ?)",
                      (pname, pdesc, st.session_state.username, current_ts()))
            conn.commit()
            st.success("Project created.")

        st.markdown("----")
        st.subheader("Share Project with Users")
        c.execute("SELECT project_id, project_name FROM projects")
        projects = c.fetchall()
        if projects:
            proj_map = {str(p[0]): p[1] for p in projects}
            pid = st.selectbox("Select project to share", [f"{p[0]} - {p[1]}" for p in projects], key="share_proj")
            pid_val = int(pid.split(" - ")[0])
            st.write("Share with (type username) :")
            share_user = st.text_input("Username to share", key="share_user")
            if st.button("Share"):
                c.execute("INSERT INTO project_shares (project_id, username) VALUES (?, ?)", (pid_val, share_user))
                conn.commit()
                st.success(f"Shared project with {share_user}.")
        else:
            st.info("No projects yet.")

    # ---------- Create MoM ----------
    with tabs[2]:
        st.header("Create Minutes of Meeting")
        c.execute("SELECT project_id, project_name FROM projects")
        all_projects = c.fetchall()
        if not all_projects:
            st.info("Create a project first.")
        else:
            proj_choice = st.selectbox("Select project", [f"{p[0]} - {p[1]}" for p in all_projects], key="mom_proj")
            proj_id = int(proj_choice.split(" - ")[0])
            mom_title = st.text_input("MoM Title", key="mom_title")
            mom_desc = st.text_area("Description", key="mom_desc")
            participants = st.text_area("Participants (comma separated)", key="mom_part")
            meeting_date = st.date_input("Meeting Date", value=date.today(), key="mom_date")
            num_tasks = st.number_input("Number of tasks", min_value=1, max_value=20, value=1, key="mom_num_tasks")
            tasks_to_add = []
            for i in range(int(num_tasks)):
                st.markdown(f"**Task {i+1}**")
                ttitle = st.text_input(f"Task title {i+1}", key=f"t_title_{i}")
                tdesc = st.text_area(f"Task desc {i+1}", key=f"t_desc_{i}")
                tassignee = st.text_input(f"Assignee username {i+1}", key=f"t_assignee_{i}")
                treporter = st.text_input(f"Reporter username {i+1}", key=f"t_reporter_{i}")
                tdue = st.date_input(f"Due date {i+1}", value=date.today()+timedelta(days=3), key=f"t_due_{i}")
                tasks_to_add.append((ttitle, tdesc, tassignee, treporter, str(tdue)))

            if st.button("Save MoM"):
                # Insert mom record
                c.execute("""INSERT INTO mom_records (project_id, title, description, participants, meeting_date, created_by, created_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?)""",
                          (proj_id, mom_title, mom_desc, participants, str(meeting_date), st.session_state.username, current_ts()))
                conn.commit()
                mom_id = c.lastrowid
                # Insert tasks
                for t in tasks_to_add:
                    c.execute("""INSERT INTO tasks (mom_id, title, description, assignee, reporter, due_date, status, assignee_notes, updated_at)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                              (mom_id, t[0], t[1], t[2], t[3], t[4], "Open", "", current_ts()))
                conn.commit()

                # prepare Teams message with deep links for each task
                c.execute("SELECT task_id, title, assignee, reporter FROM tasks WHERE mom_id=?", (mom_id,))
                task_rows = c.fetchall()
                lines = [f"**Project:** {proj_map_name(proj_id)}", f"**MoM:** {mom_title}", ""]
                for tr in task_rows:
                    tid, ttitle, tassignee, treporter = tr
                    link = create_deep_link(mom_id, tid)
                    lines.append(f"- **{ttitle}** (Assignee: {tassignee} | Reporter: {treporter}) → [Open to Edit]({link})")
                teams_text = "\n".join(lines)
                send_teams_message("📝 New MoM Created", teams_text)

                st.success("MoM saved and posted to Teams with edit links.")

    # ---------- All MoMs ----------
    with tabs[3]:
        st.header("All MoMs (All projects)")
        c.execute("""SELECT m.mom_id, p.project_name, m.title, m.meeting_date, m.created_by 
                     FROM mom_records m JOIN projects p ON m.project_id=p.project_id ORDER BY m.created_at DESC""")
        rows = c.fetchall()
        for r in rows:
            mom_id, project_name, title, mdate, created_by = r
            with st.expander(f"{project_name} — {title} ({mdate})"):
                st.write(f"Created by: {created_by}")
                if st.button(f"Export PDF##{mom_id}"):
                    pdf_path = generate_pdf_for_mom(mom_id, out_path=f"mom_{mom_id}.pdf")
                    if pdf_path:
                        with open(pdf_path, "rb") as f:
                            st.download_button("Download PDF", f, file_name=pdf_path)
                # show tasks
                c.execute("SELECT task_id, title, assignee, reporter, due_date, status, assignee_notes FROM tasks WHERE mom_id=?", (mom_id,))
                tasks = c.fetchall()
                for t in tasks:
                    tid, ttitle, tass, trep, tdue, status, notes = t
                    st.markdown(f"**{ttitle}** — Assignee: {tass} | Reporter: {trep} | Due: {tdue} | Status: {status}")
                    st.caption(f"Assignee Notes: {notes or '-'}")
    # ---------- Settings ----------
    with tabs[4]:
        st.header("Settings")
        st.write("Update app config values in the top CONFIG section of app.py (SMTP, Teams webhook, APP_BASE_URL).")
        st.info("For production, do not put SMTP password in code — use environment variables or secret manager.")

# ----------------------------
# Helper to map project id to name
# ----------------------------
def proj_map_name(pid:int):
    c.execute("SELECT project_name FROM projects WHERE project_id=?", (pid,))
    r = c.fetchone()
    return r[0] if r else f"Project {pid}"

# ----------------------------
# User view: shared projects and tasks
# ----------------------------
def user_dashboard():
    st.title("👤 User Dashboard")
    st.sidebar.write(f"Signed in as: **{st.session_state.username}**")

    # Show projects shared with this user
    st.header("Projects shared with you")
    c.execute("""SELECT p.project_id, p.project_name FROM projects p 
                 JOIN project_shares s ON p.project_id=s.project_id
                 WHERE s.username=?""", (st.session_state.username,))
    shared = c.fetchall()
    if not shared:
        st.info("No projects shared with you yet.")
    else:
        sel = st.selectbox("Select project", [f"{p[0]} - {p[1]}" for p in shared], key="user_proj_select")
        pid = int(sel.split(" - ")[0])
        st.subheader("MoMs under project")
        c.execute("SELECT mom_id, title, meeting_date FROM mom_records WHERE project_id=? ORDER BY meeting_date DESC", (pid,))
        moms = c.fetchall()
        if not moms:
            st.info("No MoMs yet.")
        else:
            for mom in moms:
                mom_id, title, mdate = mom
                with st.expander(f"{title} — {mdate}"):
                    if st.button(f"Download PDF##user{mom_id}"):
                        pdf_path = generate_pdf_for_mom(mom_id, out_path=f"user_mom_{mom_id}.pdf")
                        if pdf_path:
                            with open(pdf_path, "rb") as f:
                                st.download_button("Download PDF", f, file_name=pdf_path)
                    st.markdown("**Tasks:**")
                    c.execute("SELECT task_id, title, description, assignee, reporter, due_date, status, assignee_notes FROM tasks WHERE mom_id=?", (mom_id,))
                    tasks = c.fetchall()
                    
