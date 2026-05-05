from flask import Flask, request, render_template_string, redirect, session, url_for
import hashlib
import logging
import re
import sqlite3

app = Flask(__name__)
app.secret_key = "secret-key"

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# Login failure counter used for brute-force attacks mitigation.
failed_attempts = {}

ALLOWED_GRADES = {"A+", "A", "B+", "B", "C+", "C", "D+", "D", "F"}
ALPHANUMERIC_ONLY = re.compile(r"^[A-Za-z0-9]+$")


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS grades (
            student_username TEXT PRIMARY KEY,
            course TEXT,
            grade TEXT
        )
        """
    )

    # Passwords are stored as hashes instead of plain text.
    admin_pass = hashlib.sha256("1234".encode()).hexdigest()
    student_pass = hashlib.sha256("1111".encode()).hexdigest()

    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'instructor')",
        (admin_pass,),
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'faisal', ?, 'student')",
        (student_pass,),
    )

    conn.commit()
    conn.close()


init_db()

login_page = """
<form method="POST">
    <h2>Login</h2>
    Username: <input name="username"><br><br>
    Password: <input name="password" type="password"><br><br>
    <button type="submit">Login</button>
</form>
<p><a href="/create-account">Create account</a></p>
"""

create_account_page = """
<form method="POST">
    <h2>Create Account</h2>
    Username: <input name="username"><br><br>
    Password: <input name="password" type="password"><br><br>
    <button type="submit">Create account</button>
</form>
<p><a href="/">Back to login</a></p>
"""

update_account_page = """
<form method="POST">
    <h2>Update Password</h2>
    New Password: <input name="password" type="password"><br><br>
    <button type="submit">Update password</button>
</form>
<p><a href="/logout">Logout</a></p>
"""


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        raw_password = request.form["password"]

        if not username or not raw_password:
            return "Please enter all fields"

        # Usernames and passwords must be letters and numbers only.
        if not ALPHANUMERIC_ONLY.fullmatch(username):
            return "Username must contain letters and numbers only"

        if not ALPHANUMERIC_ONLY.fullmatch(raw_password):
            return "Password must contain letters and numbers only"

        # Track repeated failed logins per username for Brute-Force mitigation.
        attempts = failed_attempts.get(username, 0)
        if attempts >= 5:
            logging.warning("Too many failed login attempts for username=%s", username)
            return "Too many failed login attempts. Try again later."

        # The submitted password is hashed before comparison with the stored hash.
        password = hashlib.sha256(raw_password.encode()).hexdigest()

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # SQL injection mitigation for login.
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            failed_attempts[username] = 0
            # Authentication success creates a session.
            session["username"] = user[1]
            session["role"] = user[3]
            logging.info("Successful login for username=%s", username)

            if user[3] == "instructor":
                return redirect(url_for("grades"))
            return redirect(url_for("view"))

        # Failed logins are counted and logged.
        failed_attempts[username] = attempts + 1
        logging.warning("Failed login for username=%s", username)
        attempts_left = 5 - failed_attempts[username]
        return (
            "<h3 style='color:red;'>Invalid username or password</h3>"
            f"<p>Attempts left: {attempts_left}</p>"
        )

    return render_template_string(login_page)


@app.route("/create-account", methods=["GET", "POST"])
def create_account():
    if request.method == "POST":
        username = request.form["username"].strip()
        raw_password = request.form["password"]

        if not username or not raw_password:
            return "Please enter all fields"

        if not ALPHANUMERIC_ONLY.fullmatch(username):
            return "Username must contain letters and numbers only"

        if not ALPHANUMERIC_ONLY.fullmatch(raw_password):
            return "Password must contain letters and numbers only"

        if len(raw_password) < 8:
            return "Password must be at least 8 characters"

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # SQL injection mitigation for duplicate check.
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            conn.close()
            return "Username already exists"

        # SQL injection mitigation for account creation.
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashlib.sha256(raw_password.encode()).hexdigest(), "student"),
        )
        conn.commit()
        conn.close()

        logging.info("Created account for username=%s", username)
        return "Account created successfully. You can now log in."

    return render_template_string(create_account_page)


@app.route("/logout")
def logout():
    # Logout removes the session
    session.clear()
    return redirect(url_for("login"))


@app.route("/update-account", methods=["GET", "POST"])
def update_account():
    # Only the logged-in user can change their own password.
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        raw_password = request.form["password"]

        if not raw_password:
            return "Please enter all fields"

        if not ALPHANUMERIC_ONLY.fullmatch(raw_password):
            return "Password must contain letters and numbers only"

        if len(raw_password) < 8:
            return "Password must be at least 8 characters"

        password = hashlib.sha256(raw_password.encode()).hexdigest()

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # SQL injection mitigation for password update.
        cursor.execute(
            "UPDATE users SET password=? WHERE username=?",
            (password, session["username"]),
        )
        conn.commit()
        conn.close()

        logging.info("Updated password for username=%s", session["username"])
        return "Password updated successfully."

    return render_template_string(update_account_page)


@app.route("/grades", methods=["GET", "POST"])
def grades():
    # Only instructors can post grades.
    if "username" not in session or session.get("role") != "instructor":
        logging.warning("Blocked non-instructor access to /grades")
        return "Access denied", 403

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if request.method == "POST":
        student = request.form["student"].strip()
        grade = request.form["grade"].strip().upper()

        if not student or not grade:
            conn.close()
            return "Please enter all fields"

        # Only accepted letter grades are allowed.
        if grade not in ALLOWED_GRADES:
            conn.close()
            return "Invalid grade"

        # SQL injection mitigation for grade update.
        cursor.execute(
            "INSERT OR REPLACE INTO grades (student_username, course, grade) VALUES (?, ?, ?)",
            (student, "Secure Software", grade),
        )
        conn.commit()
        logging.info(
            "Instructor %s posted grade for %s",
            session["username"],
            student,
        )

    conn.close()
    return render_template_string(
        """
        <h2>Instructor - Add Grade</h2>
        <form method="POST">
            Student Username: <input name="student"><br><br>
            Grade: <input name="grade"><br><br>
            <button type="submit">Add Grade</button>
        </form>
        <p>Allowed grades: A+, A, B+, B, C+, C, D+, D, F</p>
        <p><a href="/update-account">Update Password</a></p>
        <p><a href="/logout">Logout</a></p>
        """
    )


@app.route("/view")
def view():
    if "username" not in session:
        return redirect(url_for("login"))

    requested_user = request.args.get("user")

    # Students can only view their own grades.
    if session.get("role") == "student":
        username = session["username"]
        if requested_user and requested_user != username:
            logging.warning(
                "Blocked grade access by %s for %s",
                session["username"],
                requested_user,
            )
            return "Access denied", 403
    else:
        username = requested_user if requested_user else session["username"]

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # SQL injection mitigation for grade lookup.
    cursor.execute(
        "SELECT course, grade FROM grades WHERE student_username=?",
        (username,),
    )
    grades = cursor.fetchall()
    conn.close()

    return render_template_string(
        """
        <h2>Your Grades</h2>
        {% for g in grades %}
            <p>{{ g[0] }} : {{ g[1] }}</p>
        {% endfor %}
        <p><a href="/update-account">Update Password</a></p>
        <p><a href="/logout">Logout</a></p>
        """,
        grades=grades,
    )


if __name__ == "__main__":
    app.run(debug=False)
