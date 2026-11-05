import sqlite3
import time
import hashlib
import secrets
from datetime import date, datetime, timedelta
import os
try:
    import serial
    from serial.tools import list_ports
except ImportError:
    serial = None
    list_ports = None
import streamlit.components.v1 as components

import streamlit as st


# =========================================================
# APP CONFIG
# =========================================================

st.set_page_config(
    page_title="FitLife",
    page_icon="🏋️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Keep databases beside this app.py file, not in the terminal's current folder.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_DB_NAME = os.path.join(APP_DIR, "fitlife_users.db")
DB_NAME = os.path.join(APP_DIR, "fitlife.db")

# Reuse an older authentication database from the launch folder if present.
_legacy_auth_db = os.path.abspath("fitlife_users.db")
if (not os.path.exists(AUTH_DB_NAME)
        and os.path.isfile(_legacy_auth_db)
        and _legacy_auth_db != AUTH_DB_NAME):
    import shutil
    shutil.copy2(_legacy_auth_db, AUTH_DB_NAME)


# =========================================================
# AUTHENTICATION
# =========================================================

def get_auth_connection():
    return sqlite3.connect(AUTH_DB_NAME, timeout=10)


def init_auth_database():
    conn = get_auth_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()
    return password_hash, salt


def verify_password(password, password_hash, salt):
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, password_hash)


def create_user(username, password, display_name):
    username = username.strip().lower()
    display_name = display_name.strip() or username
    password_hash, salt = hash_password(password)
    conn = get_auth_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (username, password_hash, salt, display_name, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, password_hash, salt, display_name,
             datetime.now().isoformat(timespec="seconds")),
        )
        user_id = cur.lastrowid
        conn.commit()
        return user_id, None
    except sqlite3.IntegrityError:
        return None, "This username is already registered. Please use the Login tab."
    except sqlite3.Error as exc:
        return None, f"Could not save your account: {exc}"
    finally:
        conn.close()


def authenticate_user(username, password):
    username = username.strip().lower()
    if not username or not password:
        return None

    conn = get_auth_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, salt, display_name "
            "FROM users WHERE username=?",
            (username,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if row and verify_password(password, row[2], row[3]):
        return {
            "id": row[0],
            "username": row[1],
            "display_name": row[4],
        }
    return None


def render_auth_page():
    st.markdown(
        """
        <div style="text-align:center;padding:25px 0 10px 0;">
            <div style="font-size:58px;">🏋️</div>
            <div style="font-size:42px;font-weight:900;background:linear-gradient(90deg,#6c63ff,#00a8cc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">FitLife</div>
            <div style="font-size:18px;color:#666;">Your personal fitness & wellness companion</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    login_tab, signup_tab = st.tabs(["🔐 Login", "✨ Sign Up"])

    with login_tab:
        st.subheader("Welcome back!")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("🔓 Login", type="primary", use_container_width=True, key="login_button"):
            if not login_username or not login_password:
                st.warning("Please enter your username and password.")
            else:
                user = authenticate_user(login_username, login_password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user_id = user["id"]
                    st.session_state.username = user["username"]
                    st.session_state.display_name = user["display_name"]
                    st.session_state.notification_log = []
                    st.success("✅ Login successful! Welcome to FitLife.")
                    st.rerun()
                else:
                    st.error("❌ Incorrect username or password.")

    with signup_tab:
        st.subheader("Create your FitLife account")
        signup_name = st.text_input("Your Name", key="signup_name")
        signup_username = st.text_input("Choose Username", key="signup_username")
        signup_password = st.text_input("Create Password", type="password", key="signup_password")
        signup_confirm = st.text_input("Confirm Password", type="password", key="signup_confirm")

        st.caption("Use at least 6 characters for your password.")

        if st.button("✨ Create Account", type="primary", use_container_width=True, key="signup_button"):
            clean_username = signup_username.strip().lower()

            if not signup_name.strip() or not clean_username or not signup_password:
                st.warning("Please fill in all fields.")
            elif len(clean_username) < 3:
                st.warning("Username should contain at least 3 characters.")
            elif len(signup_password) < 6:
                st.warning("Password should contain at least 6 characters.")
            elif signup_password != signup_confirm:
                st.error("Passwords do not match.")
            else:
                user_id, error = create_user(
                    clean_username,
                    signup_password,
                    signup_name.strip(),
                )

                if error:
                    st.error(f"❌ {error}")
                else:
                    st.session_state.authenticated = True
                    st.session_state.user_id = user_id
                    st.session_state.username = clean_username
                    st.session_state.display_name = signup_name.strip()
                    st.session_state.notification_log = []
                    st.success("🎉 Account created successfully!")
                    st.rerun()


init_auth_database()

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    render_auth_page()
    st.stop()

# Each account gets its own FitLife database.
DB_NAME = os.path.join(APP_DIR, f"fitlife_user_{int(st.session_state.user_id)}.db")


# =========================================================
# CUSTOM UI
# =========================================================

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #f7f8ff 0%, #eef9ff 50%, #fff7fb 100%);
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #17172f 0%, #292955 100%);
    }

    [data-testid="stSidebar"] * {
        color: white !important;
    }

    .fit-title {
        font-size: 3rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 0.2rem;
        background: linear-gradient(90deg, #6c63ff, #00a8cc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .fit-subtitle {
        color: #666;
        font-size: 1rem;
        margin-bottom: 1.2rem;
    }

    .hero {
        padding: 1.7rem;
        border-radius: 24px;
        background: linear-gradient(135deg, #6c63ff, #00a8cc);
        color: white;
        box-shadow: 0 12px 28px rgba(70, 80, 180, 0.20);
        margin-bottom: 1.2rem;
    }

    .hero h2 {
        margin: 0 0 0.4rem 0;
        font-size: 1.9rem;
    }

    .hero p {
        margin: 0.2rem 0;
        font-size: 1rem;
    }

    .card {
        padding: 1rem 1.1rem;
        border-radius: 20px;
        background: rgba(255,255,255,0.92);
        border: 1px solid rgba(255,255,255,0.7);
        box-shadow: 0 8px 24px rgba(0,0,0,0.07);
        min-height: 120px;
    }

    .card-icon {
        font-size: 1.8rem;
    }

    .card-label {
        color: #777;
        font-size: 0.86rem;
        margin-top: 0.2rem;
    }

    .card-value {
        font-size: 1.7rem;
        font-weight: 800;
        margin-top: 0.15rem;
    }

    .stButton > button {
        border-radius: 14px;
        font-weight: 700;
        min-height: 42px;
    }

    div[data-testid="stMetric"] {
        background: rgba(255,255,255,0.9);
        border-radius: 16px;
        padding: 0.7rem;
        box-shadow: 0 5px 16px rgba(0,0,0,0.05);
    }

    /* FitLife dark charcoal + purple theme */
    .stApp, [data-testid="stAppViewContainer"] {
        background: radial-gradient(circle at top right, #292044 0%, #15131f 48%, #101018 100%) !important;
        color: #f4f0ff !important;
    }
    [data-testid="stHeader"] { background: rgba(16,16,24,0.88) !important; }
    [data-testid="stMain"] * { color: #f1edfa; }

    /* Readable Streamlit / BaseWeb dropdowns on the dark FitLife theme.
       Streamlit renders the opened menu in a portal, outside the main page;
       style both the closed control and the floating menu explicitly. */
    [data-testid="stSelectbox"] [data-baseweb="select"] > div,
    [data-testid="stMultiSelect"] [data-baseweb="select"] > div {
        background: #211c2d !important;
        border-color: #8a6ac0 !important;
        color: #ffffff !important;
    }
    [data-testid="stSelectbox"] [data-baseweb="select"] *,
    [data-testid="stMultiSelect"] [data-baseweb="select"] * {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
    }
    [data-baseweb="popover"],
    [data-baseweb="popover"] *,
    [data-baseweb="menu"],
    [data-baseweb="menu"] * {
        color: #211c2d !important;
        -webkit-text-fill-color: #211c2d !important;
    }
    [role="listbox"], [role="listbox"] [role="option"],
    [data-baseweb="menu"] [role="option"] {
        background: #fbf9ff !important;
        color: #211c2d !important;
        -webkit-text-fill-color: #211c2d !important;
        opacity: 1 !important;
    }
    [role="listbox"] [role="option"]:hover,
    [data-baseweb="menu"] [role="option"]:hover,
    [role="listbox"] [aria-selected="true"],
    [data-baseweb="menu"] [aria-selected="true"] {
        background: #6f4bb8 !important;
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
    }
    [data-testid="stSelectbox"] svg,
    [data-testid="stMultiSelect"] svg {
        fill: #ffffff !important;
        color: #ffffff !important;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #171322 0%, #241a38 100%) !important;
        border-right: 1px solid #3b2d55;
    }
    [data-testid="stSidebar"] * { color: #f4efff !important; }
    [data-testid="stWidgetLabel"] p, [data-testid="stCaptionContainer"] p {
        color: #c5badb !important;
    }
    [data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
    [data-testid="stDateInput"] input, [data-testid="stTimeInput"] input,
    [data-testid="stSelectbox"] div[data-baseweb="select"],
    [data-testid="stMultiSelect"] div[data-baseweb="select"],
    [data-testid="stTextArea"] textarea {
        background: #211c2d !important;
        color: #ffffff !important;
        border: 1px solid #51416f !important;
        border-radius: 10px !important;
    }
    [data-testid="stMetric"], .card {
        background: #211c2d !important;
        border: 1px solid #3d3152 !important;
        color: #f4efff !important;
        box-shadow: 0 8px 24px rgba(0,0,0,0.22) !important;
    }
    [data-testid="stMetricLabel"], [data-testid="stMetricValue"] {
        color: #f4efff !important;
    }
    .stButton > button {
        background: linear-gradient(135deg, #8055d9, #6336b5) !important;
        color: #ffffff !important;
        border: 1px solid #9a75e8 !important;
    }
    .stButton > button:hover { border-color: #c5aaff !important; }
    [data-testid="stTabs"] button { color: #ded2f4 !important; }
    [data-testid="stExpander"], [data-testid="stAlert"],
    [data-testid="stVerticalBlockBorderWrapper"] > div {
        border-color: #3d3152 !important;
    }
    hr { border-color: #403451 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DATABASE
# =========================================================

def get_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profile (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            name TEXT DEFAULT '',
            sex TEXT DEFAULT 'Prefer not to say',
            age INTEGER DEFAULT 18,
            weight REAL DEFAULT 0,
            height_cm REAL DEFAULT 0,
            photo BLOB
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_activity (
            activity_date TEXT PRIMARY KEY,
            steps INTEGER NOT NULL DEFAULT 0,
            water INTEGER NOT NULL DEFAULT 0,
            distance REAL NOT NULL DEFAULT 0,
            workout_minutes INTEGER NOT NULL DEFAULT 0,
            workouts_completed INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sleep_schedule (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sleep_time TEXT NOT NULL,
            wake_time TEXT NOT NULL,
            target_hours REAL NOT NULL,
            reminder_minutes INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS achievements (
            badge_id TEXT PRIMARY KEY,
            earned_date TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            master_enabled INTEGER NOT NULL DEFAULT 1,
            sleep_reminder INTEGER NOT NULL DEFAULT 1,
            wake_reminder INTEGER NOT NULL DEFAULT 1,
            water_reminder INTEGER NOT NULL DEFAULT 1,
            achievement_reminder INTEGER NOT NULL DEFAULT 1,
            exercise_complete INTEGER NOT NULL DEFAULT 1,
            step_goal_reminder INTEGER NOT NULL DEFAULT 1,
            hydration_goal_reminder INTEGER NOT NULL DEFAULT 1,
            daily_motivation INTEGER NOT NULL DEFAULT 1,
            water_interval INTEGER NOT NULL DEFAULT 60,
            sound_enabled INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute("PRAGMA table_info(notification_settings)")
    notification_columns = {row[1] for row in cur.fetchall()}
    if "sound_enabled" not in notification_columns:
        cur.execute(
            "ALTER TABLE notification_settings ADD COLUMN sound_enabled INTEGER NOT NULL DEFAULT 0"
        )

    cur.execute(
        "INSERT OR IGNORE INTO notification_settings (id) VALUES (1)"
    )

    conn.commit()
    conn.close()


create_tables()


# =========================================================
# DATABASE HELPERS
# =========================================================

def save_profile(name, sex, age, weight, height_cm, photo):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO profile (id, name, sex, age, weight, height_cm, photo)
        VALUES (1, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            sex=excluded.sex,
            age=excluded.age,
            weight=excluded.weight,
            height_cm=excluded.height_cm,
            photo=COALESCE(excluded.photo, profile.photo)
        """,
        (name, sex, age, weight, height_cm, photo),
    )
    conn.commit()
    conn.close()


def load_profile():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT name, sex, age, weight, height_cm, photo FROM profile WHERE id=1"
    )
    row = cur.fetchone()
    conn.close()
    return row


def save_activity(steps, water, distance, workout_minutes=0, workouts_completed=0):
    today = str(date.today())
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO daily_activity (
            activity_date, steps, water, distance, workout_minutes, workouts_completed
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(activity_date) DO UPDATE SET
            steps=excluded.steps,
            water=excluded.water,
            distance=excluded.distance,
            workout_minutes=excluded.workout_minutes,
            workouts_completed=excluded.workouts_completed
        """,
        (today, steps, water, distance, workout_minutes, workouts_completed),
    )
    conn.commit()
    conn.close()


def load_today_activity():
    today = str(date.today())
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT steps, water, distance, workout_minutes, workouts_completed
        FROM daily_activity
        WHERE activity_date=?
        """,
        (today,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def load_yesterday_steps():
    yesterday = str(date.today() - timedelta(days=1))
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT steps FROM daily_activity WHERE activity_date=?",
        (yesterday,),
    )
    row = cur.fetchone()
    conn.close()
    return row[0] if row else 0


def load_history(limit=None):
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT activity_date, steps, water, distance,
               workout_minutes, workouts_completed
        FROM daily_activity
        ORDER BY activity_date DESC
    """
    if limit is not None:
        query += " LIMIT ?"
        cur.execute(query, (limit,))
    else:
        cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows


def save_sleep(sleep_time, wake_time, target_hours, reminder_minutes):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO sleep_schedule (id, sleep_time, wake_time, target_hours, reminder_minutes)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            sleep_time=excluded.sleep_time,
            wake_time=excluded.wake_time,
            target_hours=excluded.target_hours,
            reminder_minutes=excluded.reminder_minutes
        """,
        (sleep_time, wake_time, target_hours, reminder_minutes),
    )
    conn.commit()
    conn.close()


def load_sleep():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT sleep_time, wake_time, target_hours, reminder_minutes FROM sleep_schedule WHERE id=1"
    )
    row = cur.fetchone()
    conn.close()
    return row


def load_badges():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT badge_id, earned_date FROM achievements ORDER BY earned_date")
    rows = cur.fetchall()
    conn.close()
    return rows


def save_badge(badge_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO achievements (badge_id, earned_date) VALUES (?, ?)",
        (badge_id, str(date.today())),
    )
    conn.commit()
    conn.close()


# =========================================================
# AUTOMATIC STEP SENSOR (MPU6050 + ARDUINO / ESP32)
# =========================================================

def get_sensor_ports():
    if list_ports is None:
        return []
    try:
        return [p.device for p in list_ports.comports()]
    except Exception:
        return []


def disconnect_sensor():
    conn = st.session_state.get("sensor_serial")
    try:
        if conn is not None and getattr(conn, "is_open", False):
            conn.close()
    except Exception:
        pass
    st.session_state.sensor_serial = None
    st.session_state.sensor_connected = False


def connect_sensor(port, baud=115200):
    if serial is None:
        return False, "pyserial is not installed. Run: pip install pyserial"
    disconnect_sensor()
    try:
        conn = serial.Serial(port, int(baud), timeout=0.1)
        st.session_state.sensor_serial = conn
        st.session_state.sensor_connected = True
        st.session_state.sensor_error = ""
        return True, f"Connected to {port}"
    except Exception as exc:
        st.session_state.sensor_error = str(exc)
        return False, str(exc)


def read_sensor_steps():
    conn = st.session_state.get("sensor_serial")
    if conn is None:
        return None
    latest = None
    try:
        for _ in range(30):
            if not conn.in_waiting:
                break
            raw = conn.readline().decode("utf-8", errors="ignore").strip()
            if raw.upper().startswith("STEPS:"):
                raw = raw.split(":", 1)[1].strip()
            try:
                value = int(float(raw))
                if value >= 0:
                    latest = value
            except ValueError:
                continue
        if latest is not None:
            st.session_state.sensor_raw_steps = latest
            st.session_state.sensor_last_read = datetime.now().strftime("%H:%M:%S")
            return latest
    except Exception as exc:
        st.session_state.sensor_error = str(exc)
        disconnect_sensor()
    return st.session_state.get("sensor_raw_steps")


def sync_sensor_steps():
    raw_steps = read_sensor_steps()
    if raw_steps is None:
        return
    if st.session_state.get("sensor_baseline") is None:
        st.session_state.sensor_baseline = raw_steps
    steps_today = max(0, int(raw_steps - st.session_state.sensor_baseline))
    st.session_state.sensor_steps_today = steps_today
    if steps_today > st.session_state.today_steps:
        st.session_state.today_steps = steps_today
        sync_today_to_db()


def run_sensor_fragment():
    if st.session_state.get("sensor_connected"):
        sync_sensor_steps()


# =========================================================
# NOTIFICATION SETTINGS + SMART REMINDERS
# =========================================================

def load_notification_settings():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT master_enabled, sleep_reminder, wake_reminder,
               water_reminder, achievement_reminder, exercise_complete,
               step_goal_reminder, hydration_goal_reminder,
               daily_motivation, water_interval, sound_enabled
        FROM notification_settings
        WHERE id=1
        """
    )
    row = cur.fetchone()
    conn.close()

    if row:
        return row

    return (1, 1, 1, 1, 1, 1, 1, 1, 1, 60, 0)


def save_notification_settings(
    master_enabled,
    sleep_reminder,
    wake_reminder,
    water_reminder,
    achievement_reminder,
    exercise_complete,
    step_goal_reminder,
    hydration_goal_reminder,
    daily_motivation,
    water_interval,
    sound_enabled,
):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO notification_settings (
            id, master_enabled, sleep_reminder, wake_reminder,
            water_reminder, achievement_reminder, exercise_complete,
            step_goal_reminder, hydration_goal_reminder,
            daily_motivation, water_interval, sound_enabled
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            master_enabled=excluded.master_enabled,
            sleep_reminder=excluded.sleep_reminder,
            wake_reminder=excluded.wake_reminder,
            water_reminder=excluded.water_reminder,
            achievement_reminder=excluded.achievement_reminder,
            exercise_complete=excluded.exercise_complete,
            step_goal_reminder=excluded.step_goal_reminder,
            hydration_goal_reminder=excluded.hydration_goal_reminder,
            daily_motivation=excluded.daily_motivation,
            water_interval=excluded.water_interval,
            sound_enabled=excluded.sound_enabled
        """,
        (
            int(master_enabled),
            int(sleep_reminder),
            int(wake_reminder),
            int(water_reminder),
            int(achievement_reminder),
            int(exercise_complete),
            int(step_goal_reminder),
            int(hydration_goal_reminder),
            int(daily_motivation),
            int(water_interval),
            int(sound_enabled),
        ),
    )
    conn.commit()
    conn.close()


def play_notification_sound():
    """Play a short browser beep. Browser autoplay policies may require a prior user interaction."""
    components.html(
        """
        <script>
        (() => {
            try {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                if (!AudioContext) return;
                const ctx = new AudioContext();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = "sine";
                osc.frequency.value = 880;
                gain.gain.setValueAtTime(0.0001, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.16, ctx.currentTime + 0.02);
                gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.45);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.5);
            } catch (e) {}
        })();
        </script>
        """,
        height=0,
    )


def render_notification_banner(notification):
    if not notification:
        return

    title = notification.get("title", "FitLife Reminder")
    message = notification.get("message", "")
    icon = notification.get("icon", "🔔")
    created = notification.get("created", time.time())

    st.markdown(
        f"""
        <div id="fitlife-notification" style="
            position:fixed;
            top:18px;
            right:24px;
            z-index:999999;
            width:min(420px, calc(100vw - 48px));
            padding:18px 20px;
            border-radius:18px;
            background:linear-gradient(135deg,#ffffff,#f6f5ff);
            border:1px solid rgba(108,99,255,.25);
            box-shadow:0 16px 40px rgba(0,0,0,.18);
            animation:fitlifeSlideIn .35s ease-out;
        " data-created="{created}">
            <div style="font-size:14px;font-weight:800;color:#6c63ff;text-transform:uppercase;letter-spacing:.5px;">🔔 FitLife Notification</div>
            <div style="font-size:23px;font-weight:900;margin-top:5px;">{icon} {title}</div>
            <div style="font-size:15px;margin-top:7px;color:#555;line-height:1.45;">{message}</div>
        </div>
        <style>
        @keyframes fitlifeSlideIn {{
            from {{ opacity:0; transform:translateY(-12px) translateX(16px); }}
            to {{ opacity:1; transform:translateY(0) translateX(0); }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    components.html(
        f"""
        <script>
        setTimeout(() => {{
            const el = document.getElementById('fitlife-notification');
            if (el) {{
                el.style.transition = 'opacity .5s ease, transform .5s ease';
                el.style.opacity = '0';
                el.style.transform = 'translateY(-10px)';
            }}
        }}, 7000);
        </script>
        """,
        height=0,
    )


def notify_user(title, message, icon="🔔", play_sound=True):
    settings = load_notification_settings()
    if settings[0] != 1:
        return

    notification = {
        "title": title,
        "message": message,
        "icon": icon,
        "created": time.time(),
    }

    st.session_state.active_notification = notification

    if "notification_log" not in st.session_state:
        st.session_state.notification_log = []

    st.session_state.notification_log.insert(0, notification)
    st.session_state.notification_log = st.session_state.notification_log[:8]

    st.toast(f"{icon} {title}: {message}", icon=icon)

    if play_sound and settings[10] == 1:
        play_notification_sound()

    render_notification_banner(notification)


def show_notification(message, icon="🔔"):
    notify_user("FitLife Reminder", message, icon)


def notify_badges(new_badges):
    settings = load_notification_settings()
    if settings[0] != 1 or settings[4] != 1:
        return

    for icon, title in new_badges:
        notify_user(
            "Achievement Unlocked",
            f"You earned {title}!",
            "🏆",
        )


def check_time_notifications():
    settings = load_notification_settings()

    (
        master_enabled,
        sleep_enabled,
        wake_enabled,
        water_enabled,
        _,
        _,
        _,
        _,
        motivation_enabled,
        water_interval,
        _,
    ) = settings

    if not master_enabled:
        return

    now = datetime.now()

    # Sleep reminder with a small grace window so a 60-second refresh cannot miss it.
    if sleep_enabled:
        sleep_time = st.session_state.get("sleep_time")
        reminder_minutes = int(st.session_state.get("sleep_reminder_minutes", 30))

        if sleep_time:
            sleep_dt = datetime.combine(now.date(), sleep_time)
            reminder_dt = sleep_dt - timedelta(minutes=reminder_minutes)
            key = f"sleep:{now.date()}:{reminder_dt.strftime('%Y-%m-%d %H:%M')}"
            delta = (now - reminder_dt).total_seconds()

            if 0 <= delta < 120 and st.session_state.get("last_scheduled_notification") != key:
                notify_user(
                    "Time to Get Ready for Bed",
                    "Start winding down and prepare for your scheduled sleep time.",
                    "😴",
                )
                st.session_state.last_scheduled_notification = key

    # Wake-up reminder.
    if wake_enabled:
        wake_time = st.session_state.get("wake_time")
        if wake_time:
            wake_dt = datetime.combine(now.date(), wake_time)
            key = f"wake:{now.date()}:{wake_dt.strftime('%Y-%m-%d %H:%M')}"
            delta = (now - wake_dt).total_seconds()

            if 0 <= delta < 120 and st.session_state.get("last_wake_notification") != key:
                notify_user(
                    "Good Morning!",
                    "Your FitLife routine is ready for a fresh start.",
                    "🌅",
                )
                st.session_state.last_wake_notification = key

    # Water reminder based on the selected interval from 08:00.
    if water_enabled:
        start_minutes = 8 * 60
        now_minutes = now.hour * 60 + now.minute
        interval = max(30, int(water_interval))

        if now_minutes >= start_minutes:
            slot = (now_minutes - start_minutes) // interval
            target_minutes = start_minutes + slot * interval
            target_hour = target_minutes // 60
            target_minute = target_minutes % 60
            target_dt = now.replace(
                hour=target_hour % 24,
                minute=target_minute,
                second=0,
                microsecond=0,
            )
            key = f"water:{now.date()}:{target_minutes}"
            delta = (now - target_dt).total_seconds()

            if 0 <= delta < 120 and st.session_state.get("last_water_notification") != key:
                if st.session_state.water < 8:
                    remaining = 8 - st.session_state.water
                    notify_user(
                        "Time for a Water Break",
                        f"Have some water when convenient. {remaining} glass(es) remain in today's tracker.",
                        "💧",
                    )
                st.session_state.last_water_notification = key

    # Daily motivation once a day.
    if motivation_enabled:
        today_key = str(now.date())
        if st.session_state.get("last_motivation_date") != today_key:
            messages = [
                "Small consistent actions can build strong habits.",
                "Keep moving at your own comfortable pace.",
                "Stay hydrated and take regular breaks.",
                "Every completed workout is a small win.",
                "A healthy routine also makes room for rest.",
                "Consistency matters more than perfection.",
            ]
            import random
            notify_user("Daily Motivation", random.choice(messages), "🌟")
            st.session_state.last_motivation_date = today_key


# =========================================================
# LIVE NOTIFICATION CHECK
# =========================================================

def run_live_notifications():
    check_time_notifications()


# =========================================================
# GENERAL HELPERS
# =========================================================

def calculate_bmi(weight, height_cm):
    if weight <= 0 or height_cm <= 0:
        return None
    height_m = height_cm / 100
    return weight / (height_m * height_m)


def calculate_distance(steps, stride_cm=70.0):
    return (steps * stride_cm) / 100000


def duration_from_times(sleep_time, wake_time):
    today = date.today()
    start = datetime.combine(today, sleep_time)
    end = datetime.combine(today, wake_time)
    if end <= start:
        end += timedelta(days=1)
    return (end - start).total_seconds() / 3600


def award_badges():
    steps = st.session_state.today_steps
    water = st.session_state.water
    distance = calculate_distance(steps, st.session_state.stride_cm)
    step_goal = st.session_state.steps_goal
    distance_goal = st.session_state.distance_goal

    earned_now = []

    badge_rules = [
        ("first_1k", steps >= 1000, "👣", "First 1K"),
        ("five_k", steps >= 5000, "🔥", "5K Mover"),
        ("step_goal", steps >= step_goal, "🎯", "Goal Crusher"),
        ("one_km", distance >= 1, "📏", "1 KM Walker"),
        ("distance_goal", distance >= distance_goal, "🧭", "Distance Champion"),
        ("water_4", water >= 4, "💧", "Hydration Starter"),
        ("water_8", water >= 8, "🏆", "Hydration Hero"),
    ]

    existing = {row[0] for row in load_badges()}

    for badge_id, condition, icon, title in badge_rules:
        if condition and badge_id not in existing:
            save_badge(badge_id)
            earned_now.append((icon, title))

    return earned_now


def sync_today_to_db():
    save_activity(
        st.session_state.today_steps,
        st.session_state.water,
        calculate_distance(
            st.session_state.today_steps,
            st.session_state.stride_cm,
        ),
        st.session_state.workout_minutes,
        st.session_state.workouts_completed,
    )


# =========================================================
# LOAD SAVED DATA
# =========================================================

profile = load_profile()
today_activity = load_today_activity()
sleep_saved = load_sleep()

if "profile_name" not in st.session_state:
    st.session_state.profile_name = profile[0] if profile else ""

if "profile_sex" not in st.session_state:
    st.session_state.profile_sex = profile[1] if profile else "Prefer not to say"

if "profile_age" not in st.session_state:
    st.session_state.profile_age = profile[2] if profile else 18

if "profile_weight" not in st.session_state:
    st.session_state.profile_weight = profile[3] if profile else 0.0

if "profile_height_cm" not in st.session_state:
    st.session_state.profile_height_cm = profile[4] if profile else 0.0

if "profile_photo" not in st.session_state:
    st.session_state.profile_photo = profile[5] if profile else None

if "today_steps" not in st.session_state:
    st.session_state.today_steps = today_activity[0] if today_activity else 0

if "water" not in st.session_state:
    st.session_state.water = today_activity[1] if today_activity else 0

if "workout_minutes" not in st.session_state:
    st.session_state.workout_minutes = today_activity[3] if today_activity else 0

if "workouts_completed" not in st.session_state:
    st.session_state.workouts_completed = today_activity[4] if today_activity else 0

if "steps_goal" not in st.session_state:
    st.session_state.steps_goal = 5000

if "distance_goal" not in st.session_state:
    st.session_state.distance_goal = 3.0

if "stride_cm" not in st.session_state:
    st.session_state.stride_cm = 70.0

if "sleep_time" not in st.session_state:
    st.session_state.sleep_time = (
        datetime.strptime(sleep_saved[0], "%H:%M").time()
        if sleep_saved
        else datetime.strptime("22:30", "%H:%M").time()
    )

if "wake_time" not in st.session_state:
    st.session_state.wake_time = (
        datetime.strptime(sleep_saved[1], "%H:%M").time()
        if sleep_saved
        else datetime.strptime("06:30", "%H:%M").time()
    )

if "sleep_target" not in st.session_state:
    st.session_state.sleep_target = sleep_saved[2] if sleep_saved else 8.0

if "sleep_reminder_minutes" not in st.session_state:
    st.session_state.sleep_reminder_minutes = sleep_saved[3] if sleep_saved else 30

if "last_scheduled_notification" not in st.session_state:
    st.session_state.last_scheduled_notification = None

if "last_wake_notification" not in st.session_state:
    st.session_state.last_wake_notification = None

if "last_water_notification" not in st.session_state:
    st.session_state.last_water_notification = None

if "last_motivation_date" not in st.session_state:
    st.session_state.last_motivation_date = None

if "active_notification" not in st.session_state:
    st.session_state.active_notification = None

if "notification_log" not in st.session_state:
    st.session_state.notification_log = []

if "sensor_serial" not in st.session_state:
    st.session_state.sensor_serial = None

if "sensor_connected" not in st.session_state:
    st.session_state.sensor_connected = False

if "sensor_raw_steps" not in st.session_state:
    st.session_state.sensor_raw_steps = 0

if "sensor_steps_today" not in st.session_state:
    st.session_state.sensor_steps_today = 0

if "sensor_baseline" not in st.session_state:
    st.session_state.sensor_baseline = None

if "sensor_base_today" not in st.session_state:
    st.session_state.sensor_base_today = int(st.session_state.today_steps)

if "sensor_last_read" not in st.session_state:
    st.session_state.sensor_last_read = "--"

if "sensor_error" not in st.session_state:
    st.session_state.sensor_error = ""


# =========================================================
# LIVE SMART NOTIFICATIONS
# =========================================================

if hasattr(st, "fragment"):
    @st.fragment(run_every="60s")
    def _fitlife_live_notifications():
        run_live_notifications()

    _fitlife_live_notifications()

    @st.fragment(run_every="1s")
    def _fitlife_sensor_live():
        run_sensor_fragment()

    _fitlife_sensor_live()
else:
    run_live_notifications()
    run_sensor_fragment()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🏋️ FitLife")
st.sidebar.caption("Fitness • Wellness • Progress")
st.sidebar.write(f"👤 **{st.session_state.get('display_name') or st.session_state.get('username')}**")
st.sidebar.caption(f"Signed in as @{st.session_state.get('username')}")

if st.sidebar.button("🚪 Logout", key="logout_button", use_container_width=True):
    for key in [
        "authenticated", "user_id", "username", "display_name",
        "profile_name", "profile_sex", "profile_age", "profile_weight",
        "profile_height_cm", "profile_photo", "active_notification",
        "notification_log",
    ]:
        st.session_state.pop(key, None)
    st.rerun()

# Mobile-friendly navigation: visible directly on the main page.
# This avoids relying on Streamlit's collapsed sidebar on phones.
page = st.selectbox(
    "📱 Navigate FitLife",
    [
        "🏠 Dashboard",
        "🏋️ Workouts",
        "📝 Exercises",
        "👣 Steps & Distance",
        "💧 Water",
        "😴 Sleep Cycle",
        "🧮 BMI Calculator",
        "👤 Profile",
        "🏆 Achievements",
        "📊 Progress & History",
    ],
    key="main_navigation",
)

st.sidebar.divider()
st.sidebar.caption(f"Your data is stored locally in {DB_NAME}")


# =========================================================
# DASHBOARD
# =========================================================

if page == "🏠 Dashboard":

    name = st.session_state.profile_name or "Fitness Friend"
    steps = st.session_state.today_steps
    water = st.session_state.water
    distance = calculate_distance(steps, st.session_state.stride_cm)
    badges = load_badges()

    st.markdown(
        '<div class="fit-title">🏋️ FitLife</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="fit-subtitle">Your personal fitness & wellness companion</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="hero">
            <h2>Hey {name}! 👋</h2>
            <p>Ready to make today a healthy and active day?</p>
            <p>Keep moving, stay hydrated and celebrate every small win. 🌟</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cols = st.columns(5)

    metrics = [
        ("👣", "Steps", f"{steps:,}"),
        ("🎯", "Goal", f"{st.session_state.steps_goal:,}"),
        ("📏", "Distance", f"{distance:.2f} km"),
        ("💧", "Water", f"{water}/8"),
        ("🏋️", "Workouts", str(st.session_state.workouts_completed)),
    ]

    for col, (icon, label, value) in zip(cols, metrics):
        with col:
            st.markdown(
                f"""
                <div class="card">
                    <div class="card-icon">{icon}</div>
                    <div class="card-label">{label}</div>
                    <div class="card-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("👣 Step Goal")
        step_progress = min(
            steps / max(st.session_state.steps_goal, 1),
            1.0,
        )
        st.progress(step_progress)
        st.write(
            f"**{steps:,} / {st.session_state.steps_goal:,} steps**"
        )
        if steps >= st.session_state.steps_goal:
            st.success("🎯 Step goal completed!")
        else:
            st.info(
                f"{st.session_state.steps_goal - steps:,} steps remaining."
            )

    with right:
        st.subheader("💧 Hydration")
        water_progress = min(water / 8, 1.0)
        st.progress(water_progress)
        st.write(f"**{water} / 8 glasses**")
        if water >= 8:
            st.success("🏆 Hydration goal completed!")
        else:
            st.info(f"{8 - water} glasses remaining.")

    st.subheader("🏆 Recent Badges")

    if badges:
        badge_defs = {
            "first_1k": ("👣", "First 1K"),
            "five_k": ("🔥", "5K Mover"),
            "step_goal": ("🎯", "Goal Crusher"),
            "one_km": ("📏", "1 KM Walker"),
            "distance_goal": ("🧭", "Distance Champion"),
            "water_4": ("💧", "Hydration Starter"),
            "water_8": ("🏆", "Hydration Hero"),
        }
        show = badges[-4:]
        badge_cols = st.columns(len(show))
        for col, item in zip(badge_cols, reversed(show)):
            badge_id = item[0]
            icon, title = badge_defs.get(
                badge_id,
                ("🌟", "Achievement"),
            )
            with col:
                st.markdown(
                    f"""
                    <div class="card" style="text-align:center; min-height:100px;">
                        <div class="card-icon">{icon}</div>
                        <strong>{title}</strong>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.info("🌟 Your first badge is waiting for you!")

    st.subheader("💬 Daily Motivation")
    st.success(
        "Small consistent actions can build a stronger routine. Keep going! 💜"
    )

    # Notification status card
    notification_settings = load_notification_settings()
    if notification_settings[0] == 1:
        st.markdown(
            """
            <div class="card">
                <div class="card-icon">🔔</div>
                <div class="card-label">Smart Notifications</div>
                <div class="card-value">Active</div>
                <div style="margin-top:8px;">
                    Sleep • Water • Exercise • Achievements
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.info(
            "🔕 Smart notifications are OFF. Enable them from your Profile."
        )

    render_notification_banner(st.session_state.get("active_notification"))


# =========================================================
# WORKOUTS + GUIDED SESSION TIMER
# =========================================================

elif page == "🏋️ Workouts":

    st.title("🏋️ Workout Library")
    st.write(
        "Choose a workout and follow the guided session step-by-step."
    )

    workouts = [
        {
            "name": "Full Body Beginner",
            "level": "Beginner",
            "duration": 30,
            "icon": "🌱",
            "exercises": [
                "Push Ups",
                "Bodyweight Squats",
                "Lunges",
                "Plank",
            ],
        },
        {
            "name": "Lower Body",
            "level": "Moderate",
            "duration": 25,
            "icon": "🦵",
            "exercises": [
                "Bodyweight Squats",
                "Lunges",
                "Glute Bridge",
            ],
        },
        {
            "name": "Core Focus",
            "level": "Moderate",
            "duration": 20,
            "icon": "🔥",
            "exercises": [
                "Plank",
                "Glute Bridge",
                "Push Ups",
            ],
        },
    ]

    workout_names = [w["name"] for w in workouts]

    selected_workout = st.selectbox(
        "🏋️ Select Workout Session",
        workout_names,
        key="workout_session_selected",
    )

    workout = next(
        w for w in workouts
        if w["name"] == selected_workout
    )

    total_duration = workout["duration"] * 60
    exercise_count = len(workout["exercises"])

    # -----------------------------------------------------
    # SESSION PLAN
    # -----------------------------------------------------
    WARMUP_SECONDS = 120
    COOLDOWN_SECONDS = 120
    REST_SECONDS = 30 * max(exercise_count - 1, 0)

    available_work_seconds = (
        total_duration
        - WARMUP_SECONDS
        - COOLDOWN_SECONDS
        - REST_SECONDS
    )

    work_per_exercise = max(
        30,
        available_work_seconds // max(exercise_count, 1)
    )

    session_key = selected_workout.replace(" ", "_").lower()

    phase_key = f"session_phase_{session_key}"
    index_key = f"session_exercise_index_{session_key}"
    start_key = f"session_start_{session_key}"
    remaining_key = f"session_remaining_{session_key}"
    running_key = f"session_running_{session_key}"
    completed_key = f"session_completed_{session_key}"

    if phase_key not in st.session_state:
        st.session_state[phase_key] = "ready"
        st.session_state[index_key] = 0
        st.session_state[start_key] = None
        st.session_state[remaining_key] = total_duration
        st.session_state[running_key] = False
        st.session_state[completed_key] = False

    # Reset state if user changes the workout.
    state_signature = (
        f"{selected_workout}_{workout['duration']}"
    )

    if st.session_state.get("workout_state_signature") != state_signature:
        st.session_state.workout_state_signature = state_signature
        st.session_state[phase_key] = "ready"
        st.session_state[index_key] = 0
        st.session_state[start_key] = None
        st.session_state[remaining_key] = total_duration
        st.session_state[running_key] = False
        st.session_state[completed_key] = False

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "📈 Level",
            workout["level"]
        )

    with c2:
        st.metric(
            "⏱️ Session",
            f"{workout['duration']} min"
        )

    with c3:
        st.metric(
            "🏋️ Exercises",
            exercise_count
        )

    st.divider()

    st.subheader("🎯 Guided Workout Session")

    phase = st.session_state[phase_key]
    exercise_index = st.session_state[index_key]

    # -----------------------------------------------------
    # START / PAUSE / RESET LOGIC
    # -----------------------------------------------------
    if st.session_state[running_key]:
        elapsed = int(
            time.time()
            - st.session_state[start_key]
        )

        phase_duration = {
            "warmup": WARMUP_SECONDS,
            "work": work_per_exercise,
            "rest": REST_SECONDS if REST_SECONDS > 0 else 0,
            "cooldown": COOLDOWN_SECONDS,
        }.get(phase, total_duration)

        phase_elapsed = elapsed

        # Current phase countdown
        phase_remaining = max(
            0,
            phase_duration - phase_elapsed
        )

        st.session_state[remaining_key] = (
            phase_remaining
        )

        # Phase complete
        if phase_remaining == 0:

            if phase == "warmup":
                st.session_state[phase_key] = "work"
                st.session_state[start_key] = time.time()
                st.session_state[remaining_key] = work_per_exercise

            elif phase == "work":

                if exercise_index < exercise_count - 1:
                    st.session_state[phase_key] = "rest"
                    st.session_state[start_key] = time.time()
                    st.session_state[remaining_key] = REST_SECONDS
                else:
                    st.session_state[phase_key] = "cooldown"
                    st.session_state[start_key] = time.time()
                    st.session_state[remaining_key] = COOLDOWN_SECONDS

            elif phase == "rest":

                st.session_state[index_key] += 1
                st.session_state[phase_key] = "work"
                st.session_state[start_key] = time.time()
                st.session_state[remaining_key] = work_per_exercise

            elif phase == "cooldown":

                st.session_state[running_key] = False
                st.session_state[start_key] = None
                st.session_state[remaining_key] = 0
                st.session_state[phase_key] = "completed"
                st.session_state[completed_key] = True

                st.session_state.workouts_completed += 1
                st.session_state.workout_minutes += workout["duration"]
                sync_today_to_db()

                new_badges = award_badges()

                st.success(
                    f"🎉 {selected_workout} completed successfully!"
                )

                settings = load_notification_settings()

                if settings[0] == 1 and settings[5] == 1:
                    notify_user(
                        "Workout Completed",
                        f"{selected_workout} is complete. Great job!",
                        "🎉",
                    )

                notify_badges(new_badges)

    # -----------------------------------------------------
    # CURRENT PHASE / DISPLAY
    # -----------------------------------------------------
    phase = st.session_state[phase_key]
    exercise_index = st.session_state[index_key]

    if phase == "ready":
        display_title = "Ready to Start"
        display_seconds = total_duration
        display_caption = "Your full workout session is ready."

    elif phase == "warmup":
        display_title = "🔥 Warm-up"
        display_seconds = st.session_state[remaining_key]
        display_caption = "Start gently and prepare your body."

    elif phase == "work":
        current_exercise = workout["exercises"][exercise_index]
        display_title = (
            f"🏋️ Exercise {exercise_index + 1}/{exercise_count}"
        )
        display_seconds = st.session_state[remaining_key]
        display_caption = current_exercise

    elif phase == "rest":
        display_title = "⏸️ Short Rest"
        display_seconds = st.session_state[remaining_key]
        display_caption = "Take a comfortable short break."

    elif phase == "cooldown":
        display_title = "🧘 Cool-down"
        display_seconds = st.session_state[remaining_key]
        display_caption = "Slow down and finish comfortably."

    elif phase == "completed":
        display_title = "✅ Session Complete"
        display_seconds = 0
        display_caption = "Excellent work! Your session is complete."

    else:
        display_title = "Ready"
        display_seconds = total_duration
        display_caption = ""

    minutes = display_seconds // 60
    seconds = display_seconds % 60

    st.markdown(
        f"""
        <div style="
            text-align:center;
            padding:28px;
            margin:10px 0 20px 0;
            border-radius:24px;
            background:linear-gradient(135deg,#211a35,#302047);
            border:1px solid #574477;
            box-shadow:0 12px 32px rgba(0,0,0,0.30);
            color:#f4efff;
        ">
            <div style="
                font-size:18px;
                font-weight:800;
                color:#c6a8ff;
            ">
                {display_title}
            </div>

            <div style="
                font-size:64px;
                font-weight:900;
                letter-spacing:2px;
                margin-top:6px;
                color:#ffffff;
            ">
                {minutes:02d}:{seconds:02d}
            </div>

            <div style="
                font-size:16px;
                font-weight:700;
                margin-top:8px;
                color:#e5ddf2;
            ">
                {display_caption}
            </div>

            <div style="
                font-size:13px;
                opacity:0.85;
                margin-top:8px;
                color:#c5b6dc;
            ">
                Total Session: {workout['duration']} minutes
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # -----------------------------------------------------
    # PROGRESS
    # -----------------------------------------------------
    if phase in {"work", "rest", "cooldown"}:
        completed_before = WARMUP_SECONDS
        current_phase_elapsed = (
            max(
                0,
                {
                    "work": work_per_exercise,
                    "rest": REST_SECONDS,
                    "cooldown": COOLDOWN_SECONDS,
                }.get(phase, 0)
                - display_seconds
            )
        )

        exercise_progress_seconds = (
            exercise_index
            * (work_per_exercise + (30 if exercise_index > 0 else 0))
        )

        progress_seconds = (
            completed_before
            + exercise_progress_seconds
            + current_phase_elapsed
        )

        overall_progress = min(
            progress_seconds / max(total_duration, 1),
            1.0,
        )

        st.progress(overall_progress)

    # -----------------------------------------------------
    # CONTROLS
    # -----------------------------------------------------
    b1, b2, b3 = st.columns(3)

    with b1:
        if st.button(
            "▶️ Start Session",
            key=f"guided_start_{session_key}",
            use_container_width=True,
            disabled=(
                st.session_state[running_key]
                or st.session_state[completed_key]
            ),
        ):
            if phase == "ready":
                st.session_state[phase_key] = "warmup"
                st.session_state[start_key] = time.time()
                st.session_state[remaining_key] = WARMUP_SECONDS

            elif phase in {"warmup", "work", "rest", "cooldown"}:
                st.session_state[start_key] = (
                    time.time()
                    - (
                        (
                            {
                                "warmup": WARMUP_SECONDS,
                                "work": work_per_exercise,
                                "rest": REST_SECONDS,
                                "cooldown": COOLDOWN_SECONDS,
                            }.get(phase, 0)
                        )
                        - st.session_state[remaining_key]
                    )
                )

            st.session_state[running_key] = True
            st.rerun()

    with b2:
        if st.button(
            "⏸️ Pause",
            key=f"guided_pause_{session_key}",
            use_container_width=True,
            disabled=not st.session_state[running_key],
        ):
            elapsed = int(
                time.time()
                - st.session_state[start_key]
            )

            phase_duration = {
                "warmup": WARMUP_SECONDS,
                "work": work_per_exercise,
                "rest": REST_SECONDS,
                "cooldown": COOLDOWN_SECONDS,
            }.get(phase, 0)

            st.session_state[remaining_key] = max(
                0,
                phase_duration - elapsed
            )

            st.session_state[running_key] = False
            st.session_state[start_key] = None
            st.rerun()

    with b3:
        if st.button(
            "🔄 Reset",
            key=f"guided_reset_{session_key}",
            use_container_width=True,
        ):
            st.session_state[phase_key] = "ready"
            st.session_state[index_key] = 0
            st.session_state[start_key] = None
            st.session_state[remaining_key] = total_duration
            st.session_state[running_key] = False
            st.session_state[completed_key] = False
            st.rerun()

    if st.session_state[running_key]:
        st.success("🟢 Guided workout is in progress")
        time.sleep(1)
        st.rerun()
    elif st.session_state[completed_key]:
        st.success(
            "🏆 Great job! You completed the entire workout session."
        )
    else:
        st.info(
            "⏸️ Ready. Start the session when you're comfortable."
        )

    st.divider()

    # -----------------------------------------------------
    # SESSION PLAN
    # -----------------------------------------------------
    st.subheader("📋 Today's Session Plan")

    st.write(
        f"🔥 Warm-up — {WARMUP_SECONDS // 60} min"
    )

    for number, exercise in enumerate(
        workout["exercises"],
        start=1,
    ):
        st.write(
            f"**{number}. {exercise}** — "
            f"{work_per_exercise // 60} min "
            f"{work_per_exercise % 60:02d} sec"
        )

        if number < exercise_count:
            st.caption(
                f"⏸️ {REST_SECONDS} sec rest after this exercise"
            )

    st.write(
        f"🧘 Cool-down — {COOLDOWN_SECONDS // 60} min"
    )

# =========================================================
# EXERCISES + FIXED TIMERS
# =========================================================

elif page == "📝 Exercises":

    st.title("📝 Exercise Library")
    st.write(
        "Choose an exercise to view instructions and use its fixed exercise timer."
    )

    exercise_data = {
        "Squats": {
            "muscle": "Legs & Glutes",
            "icon": "🦵",
            "instruction": "Lower your body with control, keep your chest comfortable and return to standing.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
        "Push Ups": {
            "muscle": "Chest & Arms",
            "icon": "💪",
            "instruction": "Keep your body aligned and lower and raise your body with controlled movement.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
        "Lunges": {
            "muscle": "Legs",
            "icon": "🚶",
            "instruction": "Step forward, lower with control, then return to your starting position.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
        "Plank": {
            "muscle": "Core",
            "icon": "🔥",
            "instruction": "Keep your body stable and aligned while holding the position.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
        "Jumping Jacks": {
            "muscle": "Full Body",
            "icon": "⚡",
            "instruction": "Move your arms and legs out and in with a steady rhythm.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
        "Glute Bridge": {
            "muscle": "Glutes",
            "icon": "🌉",
            "instruction": "Lift your hips smoothly and lower with control.",
            "beginner": 30,
            "moderate": 45,
            "hard": 60,
        },
    }

    selected = st.selectbox(
        "🏋️ Choose Exercise",
        list(exercise_data.keys()),
        key="exercise_selected",
    )

    info = exercise_data[selected]

    difficulty = st.selectbox(
        "📈 Difficulty",
        ["Beginner", "Moderate", "Hard"],
        key=f"difficulty_{selected}",
    )

    seconds_by_level = {
        "Beginner": info["beginner"],
        "Moderate": info["moderate"],
        "Hard": info["hard"],
    }

    fixed_duration = seconds_by_level[difficulty]

    timer_remaining_key = f"timer_remaining_{selected}_{difficulty}"
    timer_running_key = f"timer_running_{selected}_{difficulty}"
    timer_start_key = f"timer_start_{selected}_{difficulty}"
    timer_total_key = f"timer_total_{selected}_{difficulty}"

    if timer_remaining_key not in st.session_state:
        st.session_state[timer_remaining_key] = fixed_duration
        st.session_state[timer_running_key] = False
        st.session_state[timer_start_key] = None
        st.session_state[timer_total_key] = fixed_duration

    if st.session_state[timer_total_key] != fixed_duration:
        st.session_state[timer_remaining_key] = fixed_duration
        st.session_state[timer_total_key] = fixed_duration
        st.session_state[timer_running_key] = False
        st.session_state[timer_start_key] = None

    st.markdown(
        f"""
        <div class="card" style="text-align:center; margin:1rem 0;">
            <div class="card-icon" style="font-size:3.2rem;">{info['icon']}</div>
            <div style="font-size:1.35rem;font-weight:800;">{selected}</div>
            <div style="margin-top:6px;opacity:0.75;">Exercise timer and instructions</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("💪 Target Area", info["muscle"])
    with c2:
        st.metric("📈 Level", difficulty)
    with c3:
        st.metric("⏱️ Fixed Timer", f"{fixed_duration}s")

    st.info(f"💡 **How to perform:** {info['instruction']}")

    # -----------------------------------------------------
    # TIMER UPDATE
    # -----------------------------------------------------

    if st.session_state[timer_running_key]:
        elapsed = int(time.time() - st.session_state[timer_start_key])
        remaining = max(0, st.session_state[timer_total_key] - elapsed)
        st.session_state[timer_remaining_key] = remaining

        if remaining == 0:
            st.session_state[timer_running_key] = False
            st.session_state[timer_start_key] = None
            st.session_state.workouts_completed += 1
            st.session_state.workout_minutes += max(1, fixed_duration // 60)
            sync_today_to_db()
            new_badges = award_badges()
            st.success(f"🎉 {selected} completed!")

            settings = load_notification_settings()
            if settings[0] == 1 and settings[5] == 1:
                st.toast(
                    f"🏋️ Amazing! {selected} completed!",
                    icon="🎉",
                )

            notify_badges(new_badges)

    remaining = st.session_state[timer_remaining_key]
    mm = remaining // 60
    ss = remaining % 60

    st.markdown(
        f"<div style='text-align:center;font-size:58px;font-weight:800;padding:12px;'>⏱️ {mm:02d}:{ss:02d}</div>",
        unsafe_allow_html=True,
    )

    b1, b2, b3 = st.columns(3)

    with b1:
        if st.button(
            "▶️ Start",
            key=f"start_{selected}_{difficulty}",
            use_container_width=True,
            disabled=st.session_state[timer_running_key],
        ):
            st.session_state[timer_start_key] = time.time()
            st.session_state[timer_running_key] = True
            st.rerun()

    with b2:
        if st.button(
            "⏸️ Pause",
            key=f"pause_{selected}_{difficulty}",
            use_container_width=True,
            disabled=not st.session_state[timer_running_key],
        ):
            elapsed = int(time.time() - st.session_state[timer_start_key])
            st.session_state[timer_remaining_key] = max(
                0,
                st.session_state[timer_total_key] - elapsed,
            )
            st.session_state[timer_running_key] = False
            st.session_state[timer_start_key] = None
            st.rerun()

    with b3:
        if st.button(
            "🔄 Reset",
            key=f"reset_{selected}_{difficulty}",
            use_container_width=True,
        ):
            st.session_state[timer_remaining_key] = fixed_duration
            st.session_state[timer_running_key] = False
            st.session_state[timer_start_key] = None
            st.rerun()

    if st.session_state[timer_running_key]:
        st.success("🟢 Exercise in progress")
        time.sleep(1)
        st.rerun()
    else:
        st.info("⏸️ Ready")


# =========================================================
# STEPS & DISTANCE
# =========================================================

elif page == "👣 Steps & Distance":

    st.title("👣 Steps & Distance")

    st.subheader("🎯 Daily Goals")

    g1, g2 = st.columns(2)

    with g1:
        new_step_goal = st.number_input(
            "Daily Step Goal",
            min_value=100,
            max_value=50000,
            value=int(st.session_state.steps_goal),
            step=100,
            key="step_goal_input",
        )

    with g2:
        new_distance_goal = st.number_input(
            "Daily Distance Goal (km)",
            min_value=0.1,
            max_value=100.0,
            value=float(st.session_state.distance_goal),
            step=0.5,
            key="distance_goal_input",
        )

    st.caption(
        "Choose a comfortable goal for yourself. A single BMI value should not be used to prescribe a step goal."
    )

    if st.button(
        "💾 Save Goals",
        key="save_activity_goals",
        use_container_width=True,
    ):
        st.session_state.steps_goal = new_step_goal
        st.session_state.distance_goal = new_distance_goal
        st.success("🎯 Goals saved!")

    st.divider()

    st.subheader("📡 Automatic Step Counter")
    st.write("Connect an MPU6050 accelerometer using Arduino Uno/Nano or ESP32 to count steps automatically.")

    if serial is None:
        st.warning("⚠️ Sensor support requires pyserial. Install with: pip install pyserial")

    ports = get_sensor_ports()
    options = ports if ports else ["No COM port detected"]

    sc1, sc2, sc3 = st.columns([2, 1, 1])
    with sc1:
        sensor_port = st.selectbox("USB / COM Port", options, key="sensor_port_select")
    with sc2:
        sensor_baud = st.selectbox("Baud Rate", [115200, 9600], index=0, key="sensor_baud_select")
    with sc3:
        st.metric("📡 Status", "Connected" if st.session_state.sensor_connected else "Disconnected")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔌 Connect Sensor", key="connect_sensor_button", use_container_width=True, disabled=(sensor_port == "No COM port detected" or serial is None)):
            ok, message = connect_sensor(sensor_port, sensor_baud)
            if ok:
                st.session_state.sensor_baseline = None
                st.success("✅ " + message)
                st.rerun()
            else:
                st.error("❌ " + message)
    with c2:
        if st.button("⛓️ Disconnect Sensor", key="disconnect_sensor_button", use_container_width=True, disabled=not st.session_state.sensor_connected):
            disconnect_sensor()
            st.success("Sensor disconnected.")
            st.rerun()

    if st.session_state.sensor_connected:
        st.success(f"🟢 Automatic counting active — {int(st.session_state.sensor_steps_today):,} sensor steps | Last reading: {st.session_state.sensor_last_read}")
    elif st.session_state.sensor_error:
        st.error(f"Sensor error: {st.session_state.sensor_error}")
    else:
        st.info("Connect the sensor and keep it attached securely while walking. The counter updates automatically.")

    st.caption("Hardware: MPU6050 + Arduino/ESP32. Manual entry is kept below as a backup.")

    st.divider()
    st.subheader("✍️ Manual Step Entry (Backup)")

    y_steps = st.number_input("Yesterday's Steps", min_value=0, max_value=100000, value=int(load_yesterday_steps()), step=100, key="yesterday_input")

    t_steps = st.number_input("Today's Steps", min_value=0, max_value=100000, value=int(st.session_state.today_steps), step=100, key="today_input")

    stride = st.number_input("Estimated Average Stride (cm)", min_value=20.0, max_value=150.0, value=float(st.session_state.stride_cm), step=1.0, key="stride_input")

    if st.button("📊 Save Today's Activity", key="save_steps_activity", use_container_width=True):
        st.session_state.today_steps = t_steps
        st.session_state.stride_cm = stride
        distance = calculate_distance(t_steps, stride)
        save_activity(t_steps, st.session_state.water, distance, st.session_state.workout_minutes, st.session_state.workouts_completed)

        if t_steps > y_steps:
            st.success(f"🔥 Great! You did {t_steps - y_steps:,} more steps than yesterday!")
            st.toast("🏆 Great improvement!", icon="🔥")
        elif t_steps == y_steps:
            st.info("👍 You matched yesterday's steps!")
        else:
            st.info("💙 Keep moving at a comfortable pace.")

        new_badges = award_badges()
        settings = load_notification_settings()
        if settings[0] == 1 and settings[6] == 1 and t_steps >= st.session_state.steps_goal:
            notify_user("Step Goal Completed", "Amazing! You completed today's step goal.", "🎯")
        notify_badges(new_badges)

    distance = calculate_distance(
        st.session_state.today_steps,
        st.session_state.stride_cm,
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("👣 Steps", f"{st.session_state.today_steps:,}")

    with c2:
        st.metric("📏 Distance", f"{distance:.2f} km")

    with c3:
        st.metric("🎯 Goal", f"{st.session_state.steps_goal:,}")

    st.write("Step Goal Progress")
    st.progress(
        min(
            st.session_state.today_steps
            / max(st.session_state.steps_goal, 1),
            1.0,
        )
    )

    if distance >= st.session_state.distance_goal:
        st.success("🧭 Distance goal completed!")


# =========================================================
# WATER
# =========================================================

elif page == "💧 Water":

    st.title("💧 Water Tracker")
    st.write("Track your glasses through the day.")

    c1, c2 = st.columns(2)

    with c1:
        st.metric(
            "🥛 Today's Water",
            f"{st.session_state.water}/8",
        )

    with c2:
        st.metric("🎯 Daily Goal", "8 glasses")

    st.divider()

    a, b = st.columns(2)

    with a:
        if st.button(
            "➕ Add Glass",
            key="water_add",
            use_container_width=True,
        ):
            if st.session_state.water < 8:
                st.session_state.water += 1
            sync_today_to_db()
            new_badges = award_badges()
            notify_badges(new_badges)

            settings = load_notification_settings()
            if (
                settings[0] == 1
                and settings[7] == 1
                and st.session_state.water >= 8
            ):
                notify_user(
                    "Hydration Goal Completed",
                    "Fantastic! Today's hydration goal is complete.",
                    "💦",
                )

            st.rerun()

    with b:
        if st.button(
            "➖ Remove Glass",
            key="water_remove",
            use_container_width=True,
        ):
            if st.session_state.water > 0:
                st.session_state.water -= 1
            sync_today_to_db()
            st.rerun()

    st.progress(min(st.session_state.water / 8, 1.0))

    if st.session_state.water >= 8:
        st.success("🏆 Hydration goal completed!")
    else:
        st.info(
            f"{8 - st.session_state.water} glasses remaining."
        )


# =========================================================
# SLEEP CYCLE
# =========================================================

elif page == "😴 Sleep Cycle":

    st.title("😴 Sleep Cycle")

    st.info(
        "Set your preferred sleep and wake-up schedule."
    )

    # -----------------------------------------------------
    # LOAD CURRENT VALUES SAFELY
    # -----------------------------------------------------

    current_sleep = st.session_state.get("sleep_time")

    current_wake = st.session_state.get("wake_time")

    if current_sleep is None:
        current_sleep = datetime.strptime(
            "22:30",
            "%H:%M"
        ).time()

    if current_wake is None:
        current_wake = datetime.strptime(
            "06:30",
            "%H:%M"
        ).time()

    current_target = st.session_state.get(
        "sleep_target",
        8.0
    )

    current_reminder = st.session_state.get(
        "sleep_reminder_minutes",
        30
    )

    # -----------------------------------------------------
    # USER INPUT
    # -----------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        sleep_input = st.time_input(
            "🌙 Sleep Time",
            value=current_sleep,
            key="sleep_cycle_time_input"
        )

    with col2:

        wake_input = st.time_input(
            "🌅 Wake-up Time",
            value=current_wake,
            key="wake_cycle_time_input"
        )

    target_input = st.number_input(
        "🎯 Target Sleep Duration (hours)",
        min_value=1.0,
        max_value=14.0,
        value=float(current_target),
        step=0.5,
        key="sleep_target_hours"
    )

    reminder_input = st.number_input(
        "🔔 Remind me before sleep (minutes)",
        min_value=5,
        max_value=180,
        value=int(current_reminder),
        step=5,
        key="sleep_reminder_minutes"
    )

    # -----------------------------------------------------
    # SAVE
    # -----------------------------------------------------

    if st.button(
        "💾 Save Sleep Schedule",
        key="save_sleep_schedule_final",
        use_container_width=True
    ):

        # Extra safety check
        if sleep_input is None or wake_input is None:

            st.error(
                "Please select both sleep and wake-up times."
            )

        else:

            # Save to session state
            st.session_state.sleep_time = sleep_input
            st.session_state.wake_time = wake_input
            st.session_state.sleep_target = target_input
            # sleep_reminder_minutes is also the key of the number_input
            # widget above. Streamlit updates it automatically; assigning
            # it again after widget creation raises StreamlitAPIException.

            # Save to SQLite
            save_sleep(
                sleep_input.strftime("%H:%M"),
                wake_input.strftime("%H:%M"),
                float(target_input),
                int(reminder_input)
            )

            st.success(
                "✅ Sleep schedule saved successfully!"
            )

    st.divider()

    # -----------------------------------------------------
    # CALCULATE SLEEP DURATION
    # -----------------------------------------------------

    today = datetime.now().date()

    sleep_datetime = datetime.combine(
        today,
        sleep_input
    )

    wake_datetime = datetime.combine(
        today,
        wake_input
    )

    # If wake time is next day
    if wake_datetime <= sleep_datetime:

        wake_datetime += timedelta(days=1)

    sleep_duration = (
        wake_datetime - sleep_datetime
    ).total_seconds() / 3600

    # -----------------------------------------------------
    # DISPLAY
    # -----------------------------------------------------

    st.subheader("🌙 Your Sleep Schedule")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "🌙 Sleep",
            sleep_input.strftime("%I:%M %p")
        )

    with col2:

        st.metric(
            "🌅 Wake",
            wake_input.strftime("%I:%M %p")
        )

    with col3:

        st.metric(
            "🛌 Scheduled Sleep",
            f"{sleep_duration:.1f} hrs"
        )

    # -----------------------------------------------------
    # TARGET CHECK
    # -----------------------------------------------------

    if sleep_duration >= target_input:

        st.success(
            "✅ Your scheduled sleep duration meets your target."
        )

    else:

        st.warning(
            f"⚠️ Your schedule gives about "
            f"{sleep_duration:.1f} hours, "
            f"while your target is {target_input:.1f} hours."
        )

    st.divider()

    # -----------------------------------------------------
    # REMINDER INFORMATION
    # -----------------------------------------------------

    st.subheader("🔔 Reminder")

    reminder_datetime = (
        sleep_datetime
        - timedelta(
            minutes=int(reminder_input)
        )
    )

    st.write(
        "🌙 Sleep reminder time: "
        f"**{reminder_datetime.strftime('%I:%M %p')}**"
    )

    st.write(
        "🌅 Wake-up time: "
        f"**{wake_input.strftime('%I:%M %p')}**"
    )

    st.info(
        "The current Streamlit version shows reminders "
        "inside the app while it is running. True phone "
        "lock-screen notifications require a separate "
        "mobile/PWA notification system."
    )

# =========================================================
# BMI
# =========================================================

elif page == "🧮 BMI Calculator":

    st.title("🧮 BMI Calculator")
    st.write(
        "Enter your details. Height can be entered in cm or feet + inches."
    )

    weight = st.number_input(
        "⚖️ Weight (kg)",
        min_value=0.0,
        max_value=300.0,
        value=(
            float(st.session_state.profile_weight)
            if st.session_state.profile_weight > 0
            else 50.0
        ),
        step=0.5,
        key="bmi_weight",
    )

    age = st.number_input(
        "🎂 Age",
        min_value=1,
        max_value=120,
        value=int(st.session_state.profile_age),
        step=1,
        key="bmi_age",
    )

    height_unit = st.radio(
        "📏 Height Unit",
        ["Centimeters (cm)", "Feet + Inches"],
        horizontal=True,
        key="bmi_height_unit",
    )

    if height_unit == "Centimeters (cm)":

        height_cm = st.number_input(
            "📏 Height (cm)",
            min_value=50.0,
            max_value=250.0,
            value=(
                float(st.session_state.profile_height_cm)
                if st.session_state.profile_height_cm > 0
                else 160.0
            ),
            step=1.0,
            key="bmi_height_cm",
        )

    else:

        c1, c2 = st.columns(2)

        with c1:
            feet = st.number_input(
                "Feet",
                min_value=1,
                max_value=8,
                value=5,
                step=1,
                key="bmi_feet",
            )

        with c2:
            inches = st.number_input(
                "Inches",
                min_value=0,
                max_value=11,
                value=3,
                step=1,
                key="bmi_inches",
            )

        height_cm = (
            feet * 30.48
            + inches * 2.54
        )

        st.info(
            f"📐 Converted height: **{height_cm:.1f} cm**"
        )

    if st.button(
        "🧮 Calculate BMI",
        key="calculate_bmi",
        use_container_width=True,
    ):

        bmi = calculate_bmi(
            weight,
            height_cm
        )

        if bmi is None:
            st.warning(
                "⚠️ Please enter a valid height and weight."
            )

        else:

            st.metric(
                "🧮 Your BMI",
                f"{bmi:.1f}"
            )

            st.divider()

            if age < 18:

                st.info(
                    "👤 Because you are under 18, adult BMI ranges "
                    "should not be used to label your BMI as safe or unsafe. "
                    "BMI for children and teenagers is interpreted using "
                    "age- and sex-specific growth charts."
                )

                st.warning(
                    "💡 Please discuss your BMI with a parent/guardian "
                    "or qualified healthcare professional if you are concerned."
                )

            else:

                # -------------------------------------------------
                # ADULT BMI RANGE
                # -------------------------------------------------

                if bmi < 18.5:

                    st.warning(
                        "🟡 Your BMI is below the usual adult healthy range."
                    )

                    st.write(
                        "This does not automatically mean that you are unhealthy. "
                        "BMI is only a screening measure."
                    )

                    status = "Below usual range"

                elif bmi < 25:

                    st.success(
                        "🟢 Your BMI is in the usual adult healthy range."
                    )

                    st.write(
                        "This is generally considered the healthy BMI range "
                        "for adults."
                    )

                    status = "Healthy range"

                elif bmi < 30:

                    st.warning(
                        "🟠 Your BMI is above the usual adult healthy range."
                    )

                    st.write(
                        "BMI alone cannot tell us about your overall health. "
                        "Consider your overall routine, fitness, and health "
                        "rather than focusing on one number."
                    )

                    status = "Above usual range"

                else:

                    st.warning(
                        "🔴 Your BMI is well above the usual adult healthy range."
                    )

                    st.write(
                        "BMI is a screening measure and should not be used "
                        "alone to judge overall health."
                    )

                    status = "Higher than usual range"

                st.markdown(
                    f"""
                    <div class="card" style="margin-top:15px;">
                        <div class="card-label">BMI Status</div>
                        <div class="card-value">{status}</div>
                        <div style="margin-top:8px;color:#666;">
                            BMI is one health indicator, not a complete health diagnosis.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.info(
                    "💡 Tip: Focus on healthy habits such as regular movement, "
                    "balanced meals, hydration, sleep and overall wellbeing."
                )

# =========================================================
# PROFILE
# =========================================================

elif page == "👤 Profile":

    st.title("👤 My Profile")

    if st.session_state.profile_photo:
        st.image(
            st.session_state.profile_photo,
            width=170,
        )

    photo = st.file_uploader(
        "📸 Upload Profile Photo",
        type=["jpg", "jpeg", "png"],
        key="profile_photo_uploader",
    )

    if photo is not None:
        st.session_state.profile_photo = photo.getvalue()
        st.image(
            st.session_state.profile_photo,
            width=170,
        )

    name = st.text_input(
        "Your Name",
        value=st.session_state.profile_name,
        key="profile_name_input",
    )

    sex = st.selectbox(
        "Sex",
        ["Prefer not to say", "Female", "Male"],
        index=["Prefer not to say", "Female", "Male"].index(
            st.session_state.profile_sex
            if st.session_state.profile_sex in [
                "Prefer not to say",
                "Female",
                "Male",
            ]
            else "Prefer not to say"
        ),
        key="profile_sex_input",
    )

    age = st.number_input(
        "Age",
        min_value=1,
        max_value=120,
        value=int(st.session_state.profile_age),
        step=1,
        key="profile_age_input",
    )

    weight = st.number_input(
        "Weight (kg)",
        min_value=0.0,
        max_value=300.0,
        value=float(st.session_state.profile_weight),
        step=0.5,
        key="profile_weight_input",
    )

    st.subheader("📏 Height")

    unit = st.radio(
        "Choose Height Unit",
        ["Centimeters (cm)", "Feet + Inches"],
        horizontal=True,
        key="profile_height_unit",
    )

    if unit == "Centimeters (cm)":

        height_cm = st.number_input(
            "Height (cm)",
            min_value=50.0,
            max_value=250.0,
            value=(
                float(st.session_state.profile_height_cm)
                if st.session_state.profile_height_cm > 0
                else 160.0
            ),
            step=1.0,
            key="profile_height_cm_input",
        )

    else:

        c1, c2 = st.columns(2)

        with c1:
            feet = st.number_input(
                "Feet",
                min_value=1,
                max_value=8,
                value=5,
                step=1,
                key="profile_feet_input",
            )

        with c2:
            inches = st.number_input(
                "Inches",
                min_value=0,
                max_value=11,
                value=3,
                step=1,
                key="profile_inches_input",
            )

        height_cm = feet * 30.48 + inches * 2.54

        st.info(
            f"📐 Converted height: **{height_cm:.1f} cm**"
        )

    if st.button(
        "💾 Save Profile",
        key="save_profile",
        use_container_width=True,
    ):

        st.session_state.profile_name = name
        st.session_state.profile_sex = sex
        st.session_state.profile_age = age
        st.session_state.profile_weight = weight
        st.session_state.profile_height_cm = height_cm

        save_profile(
            name,
            sex,
            age,
            weight,
            height_cm,
            st.session_state.profile_photo,
        )

        st.success("🎉 Profile saved permanently for your FitLife account!")

    # =====================================================
    # NOTIFICATION CENTER
    # =====================================================

    st.divider()
    st.subheader("🔔 Notification Center")
    st.write("Choose which reminders FitLife should show you.")

    current_notifications = load_notification_settings()
    (
        current_master,
        current_sleep,
        current_wake,
        current_water,
        current_achievement,
        current_exercise,
        current_step_goal,
        current_hydration,
        current_motivation,
        current_water_interval,
        current_sound_enabled,
    ) = current_notifications

    master_enabled = st.toggle(
        "🔔 Enable FitLife Notifications",
        value=bool(current_master),
        key="notification_master",
    )
    st.caption("Turn this OFF to pause every FitLife reminder.")

    sound_enabled = st.toggle(
        "🔊 Notification Sound",
        value=bool(current_sound_enabled),
        key="notification_sound",
    )
    st.caption("A short alert sound will play when FitLife can use browser audio.")

    components.html(
        """
        <button id="fitlifeSoundTest" style="padding:10px 16px;border-radius:12px;border:1px solid #d8d8ef;background:#fff;font-weight:700;cursor:pointer;">🔊 Test / Enable Sound</button>
        <script>
        document.getElementById('fitlifeSoundTest').addEventListener('click', () => {
            try {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                const ctx = new AudioContext();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.frequency.value = 880;
                gain.gain.setValueAtTime(0.0001, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.16, ctx.currentTime + 0.02);
                gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.45);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.5);
            } catch (e) {}
        });
        </script>
        """,
        height=55,
    )

    if master_enabled:
        st.markdown("### 🌙 Sleep & Daily Routine")

        n1, n2 = st.columns(2)
        with n1:
            sleep_notification = st.toggle(
                "😴 Sleep Reminder",
                value=bool(current_sleep),
                key="notification_sleep",
            )
            wake_notification = st.toggle(
                "🌅 Wake-up Reminder",
                value=bool(current_wake),
                key="notification_wake",
            )
        with n2:
            motivation_notification = st.toggle(
                "🌟 Daily Motivation",
                value=bool(current_motivation),
                key="notification_motivation",
            )
            exercise_notification = st.toggle(
                "🎉 Exercise Completed",
                value=bool(current_exercise),
                key="notification_exercise",
            )

        st.markdown("### 💧 Hydration")
        water_notification = st.toggle(
            "💧 Water Reminder",
            value=bool(current_water),
            key="notification_water",
        )

        water_interval = st.select_slider(
            "⏰ Remind me to drink water every",
            options=[30, 45, 60, 90, 120, 180],
            value=int(current_water_interval),
            format_func=lambda x: f"{x} minutes",
            key="notification_water_interval",
        )

        st.markdown("### 🏆 Progress & Achievements")
        n3, n4 = st.columns(2)
        with n3:
            achievement_notification = st.toggle(
                "🏆 Achievement Unlocked",
                value=bool(current_achievement),
                key="notification_achievement",
            )
            step_goal_notification = st.toggle(
                "🎯 Step Goal Completed",
                value=bool(current_step_goal),
                key="notification_step_goal",
            )
        with n4:
            hydration_goal_notification = st.toggle(
                "💦 Hydration Goal Completed",
                value=bool(current_hydration),
                key="notification_hydration_goal",
            )

    else:
        sleep_notification = bool(current_sleep)
        wake_notification = bool(current_wake)
        water_notification = bool(current_water)
        achievement_notification = bool(current_achievement)
        exercise_notification = bool(current_exercise)
        step_goal_notification = bool(current_step_goal)
        hydration_goal_notification = bool(current_hydration)
        motivation_notification = bool(current_motivation)
        water_interval = int(current_water_interval)
        sound_enabled = bool(current_sound_enabled)

    if st.button(
        "💾 Save Notification Preferences",
        key="save_notification_settings",
        use_container_width=True,
    ):
        save_notification_settings(
            master_enabled,
            sleep_notification,
            wake_notification,
            water_notification,
            achievement_notification,
            exercise_notification,
            step_goal_notification,
            hydration_goal_notification,
            motivation_notification,
            water_interval,
            sound_enabled,
        )
        st.success("✅ Notification preferences saved successfully!")
        st.toast("🔔 FitLife reminders are updated!", icon="✨")

    st.markdown("### 🔔 Recent Notifications")
    if st.session_state.get("notification_log"):
        for item in st.session_state.notification_log[:5]:
            created_text = datetime.fromtimestamp(item["created"]).strftime("%d %b, %I:%M %p")
            st.info(f"{item['icon']} **{item['title']}** — {item['message']}  \n\n_{created_text}_")
    else:
        st.caption("No notifications have appeared in this session yet.")

    st.divider()

    st.subheader("📋 Profile Summary")

    c1, c2 = st.columns(2)

    with c1:
        st.write(
            f"👤 **Name:** {st.session_state.profile_name or 'Not added'}"
        )
        st.write(
            f"⚧️ **Sex:** {st.session_state.profile_sex}"
        )
        st.write(
            f"🎂 **Age:** {st.session_state.profile_age}"
        )

    with c2:
        st.write(
            f"⚖️ **Weight:** {st.session_state.profile_weight:.1f} kg"
        )
        if st.session_state.profile_height_cm > 0:
            st.write(
                f"📏 **Height:** {st.session_state.profile_height_cm:.1f} cm"
            )
        else:
            st.write("📏 **Height:** Not added")

        bmi = calculate_bmi(
            st.session_state.profile_weight,
            st.session_state.profile_height_cm,
        )

        if bmi:
            st.write(f"🧮 **BMI:** {bmi:.1f}")


# =========================================================
# ACHIEVEMENTS
# =========================================================

elif page == "🏆 Achievements":

    st.title("🏆 Achievements & Badges")

    award_badges()
    earned = {row[0] for row in load_badges()}

    all_badges = [
        ("first_1k", "👣", "First 1K", "Reach 1,000 steps"),
        ("five_k", "🔥", "5K Mover", "Reach 5,000 steps"),
        ("step_goal", "🎯", "Goal Crusher", "Complete your daily step goal"),
        ("one_km", "📏", "1 KM Walker", "Reach an estimated 1 km"),
        ("distance_goal", "🧭", "Distance Champion", "Complete your distance goal"),
        ("water_4", "💧", "Hydration Starter", "Reach 4 glasses"),
        ("water_8", "🏆", "Hydration Hero", "Reach 8 glasses"),
        ("sleep", "😴", "Sleep Champion", "Keep a steady sleep routine"),
        ("workout", "🏋️", "Workout Hero", "Complete workouts"),
        ("energy", "⚡", "Energy Star", "Keep an active routine"),
    ]

    st.metric(
        "🌟 Badges Earned",
        len(earned),
    )

    columns = st.columns(3)

    for i, (badge_id, icon, title, description) in enumerate(all_badges):

        with columns[i % 3]:

            unlocked = badge_id in earned

            if unlocked:
                status = "✅ Unlocked"
                opacity = "1"
            else:
                status = "🔒 Locked"
                opacity = "0.45"

            st.markdown(
                f"""
                <div class="card" style="text-align:center; opacity:{opacity}; margin-bottom:12px;">
                    <div style="font-size:48px;">{icon}</div>
                    <strong>{title}</strong>
                    <div style="margin-top:6px;">{description}</div>
                    <div style="margin-top:10px;font-size:14px;">{status}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# =========================================================
# PROGRESS & HISTORY
# =========================================================

elif page == "📊 Progress & History":

    st.title("📊 Progress & History")

    history = load_history()

    if not history:
        st.info(
            "📭 No history yet. Add today's steps or water to start your history."
        )
    else:
        newest_first = history
        oldest_first = list(reversed(history))

        total_days = len(history)
        total_steps = sum(row[1] for row in history)
        average_steps = total_steps / total_days
        best_row = max(history, key=lambda row: row[1])
        total_distance = sum(row[3] for row in history)
        total_workouts = sum(row[5] for row in history)
        hydration_days = sum(1 for row in history if row[2] >= 8)

        c1, c2, c3, c4, c5 = st.columns(5)

        with c1:
            st.metric("📅 Active Days", total_days)

        with c2:
            st.metric("👣 Average Steps", f"{average_steps:,.0f}")

        with c3:
            st.metric("🔥 Best Day", f"{best_row[1]:,}")

        with c4:
            st.metric("📏 Total Distance", f"{total_distance:.2f} km")

        with c5:
            st.metric("🏋️ Workouts", total_workouts)

        st.divider()

        # Last 7 records only for the main charts.
        last_7 = oldest_first[-7:]

        if last_7:
            labels = [row[0] for row in last_7]

            steps_chart = {
                "Date": labels,
                "Steps": [row[1] for row in last_7],
            }

            water_chart = {
                "Date": labels,
                "Glasses": [row[2] for row in last_7],
            }

            distance_chart = {
                "Date": labels,
                "Distance (km)": [row[3] for row in last_7],
            }

            workouts_chart = {
                "Date": labels,
                "Workouts": [row[5] for row in last_7],
            }

            st.subheader("👣 Last 7 Days — Steps")
            st.line_chart(steps_chart, x="Date", y="Steps")

            st.subheader("💧 Last 7 Days — Water")
            st.bar_chart(water_chart, x="Date", y="Glasses")

            st.subheader("📏 Last 7 Days — Distance")
            st.line_chart(distance_chart, x="Date", y="Distance (km)")

            st.subheader("🏋️ Last 7 Days — Workouts")
            st.bar_chart(workouts_chart, x="Date", y="Workouts")

        st.divider()

        goal_days = sum(
            1 for row in history
            if row[1] >= st.session_state.steps_goal
        )

        goal_rate = goal_days / total_days * 100

        st.subheader("🎯 Goal Summary")

        g1, g2, g3 = st.columns(3)

        with g1:
            st.metric("Goal Days", goal_days)

        with g2:
            st.metric("Goal Success", f"{goal_rate:.1f}%")

        with g3:
            st.metric("Hydration Days", hydration_days)

        st.progress(min(goal_rate / 100, 1.0))

        if goal_rate >= 80:
            st.success("🏆 Excellent consistency!")
        elif goal_rate >= 50:
            st.info("🔥 Good progress — keep building your routine!")
        else:
            st.info("🌱 Keep recording your days and build consistency gradually.")

        st.divider()

        st.subheader("📅 Daily Records")

        for row in newest_first:
            activity_date, steps, water, distance, workout_minutes, completed = row

            with st.container(border=True):
                a1, a2, a3, a4, a5 = st.columns(5)

                with a1:
                    st.write(f"📅 **{activity_date}**")

                with a2:
                    st.write(f"👣 {steps:,}")

                with a3:
                    st.write(f"💧 {water}/8")

                with a4:
                    st.write(f"📏 {distance:.2f} km")

                with a5:
                    st.write(f"🏋️ {completed} workouts")
