


import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from flask import Flask, request, render_template, redirect, session
import hashlib, json
from modules.logger import log_action

app = Flask(__name__)
app.secret_key = "autopwnsecretkey"  # Change this in production!

def verify_user(username, password):
    with open("users.json") as f:
        users = json.load(f)
    hashed = hashlib.sha256(password.strip().encode()).hexdigest()
    if username in users and users[username]["password"] == hashed:
        return users[username]["role"]
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        role = verify_user(user, pwd)
        if role:
            session['user'] = user
            session['role'] = role
            log_action(user, "Web login successful")
            return redirect('/dashboard')
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    return render_template("dashboard.html", user=session['user'], role=session['role'])

@app.route('/exploit')
def exploit():
    if 'user' not in session:
        return redirect('/')
    if session['role'] != 'admin':
        return "Access denied"
    log_action(session['user'], "Accessed exploit route")
    return "Running AutoPwn would go here (CLI integration optional)"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)
