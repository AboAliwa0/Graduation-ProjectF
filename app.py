from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
from database import init_db, connect
from main import load_scanners

app = Flask(__name__)
app.secret_key = "secret123"
bcrypt = Bcrypt(app)

init_db()

# 🏠 Home Page
@app.route('/')
def home():
    return render_template('home.html')


# 🔐 Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # 🛡️ Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = connect()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hashed_password)
            )
            conn.commit()
        except Exception as e:
            conn.close()
            return f"Error: User already exists or database error: {e}"

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

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        # 🛡️ Verify the hashed password
        if user and bcrypt.check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            return "Invalid email or password"

    return render_template('login.html')


# 🧠 Dashboard (Scanner Page)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    scanners = load_scanners()
    results = []

    if request.method == 'POST':
        url = request.form.get("url")
        selected = request.form.getlist("vuln")

        for scanner in scanners:
            name = scanner.__name__

            if name in selected:
                try:
                    result = scanner.scan(url)
                    results.append(f"{name}: {result}")
                except Exception as e:
                    results.append(f"{name}: Error {e}")

    return render_template(
        'dashboard.html',
        results=results,
        scanners=scanners
    )


# 🚪 Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == "__main__":
    app.run(debug=True)
