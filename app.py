from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "demo-secret-key-change-this"

# Demo users stored only in memory
users = {}

# Track failed login attempts
failed_attempts = {}
MAX_ATTEMPTS = 3


@app.route("/", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username not in users:
            message = "Invalid username or password."
        elif failed_attempts.get(username, 0) >= MAX_ATTEMPTS:
            message = "Account temporarily locked due to multiple failed attempts."
        elif check_password_hash(users[username], password):
            failed_attempts[username] = 0
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            remaining = MAX_ATTEMPTS - failed_attempts[username]
            message = f"Invalid password. Attempts remaining: {remaining}"

    return render_template("login.html", message=message)


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users:
            message = "Username already exists."
        elif len(password) < 8:
            message = "Password must contain at least 8 characters."
        else:
            users[username] = generate_password_hash(password, method="pbkdf2:sha256")
            failed_attempts[username] = 0
            message = "Registration successful. You can now log in."

    return render_template("register.html", message=message)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(port=5001, debug=True)