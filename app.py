from flask import Flask, render_template, request, redirect, session
from database import init_db, connect
from main import load_scanners
from vulnerabilities.auth_scanner import check_broken_auth
from vulnerabilities.ssrf_scanner import check_ssrf_basic

app = Flask(__name__)
app.secret_key = "secret123"

init_db()

# 🔐 Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)",
                           (email, password))
            conn.commit()
        except:
            return "User already exists"

        conn.close()
        return redirect('/login')

    return render_template('register.html')


# 🔑 Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=? AND password=?",
                       (email, password))

        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            return redirect('/')
        else:
            return "Invalid email or password"

    return render_template('login.html')


# 🏠 Dashboard
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect('/login')

    scanners = load_scanners()  # 👈 مهم
    results = []

    if request.method == 'POST':
        url = request.form.get("url")
        selected = request.form.getlist("vulns")

        for scanner in scanners:
            name = scanner.__name__

            if name in selected:
                try:
                    result = scanner.scan(url)
                    results.append(f"{name}: {result}")
                except Exception as e:
                    results.append(f"{name}: Error {e}")

    return render_template('dashboard.html', results=results, scanners=scanners)


# 🚪 Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == "__main__":
    app.run(debug=True)