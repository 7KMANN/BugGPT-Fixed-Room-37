from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a secure random key in production

def init_db():
    conn = sqlite3.connect('social_network.db')
    c = conn.cursor()
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    # Create posts table to simulate a social feed
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    # Add some test users
    c.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
              ('admin', hashlib.sha256('password123'.encode()).hexdigest()))
    c.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
              ('alice', hashlib.sha256('alicepwd'.encode()).hexdigest()))
    conn.commit()
    # Add some test posts
    c.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
              (1, 'Welcome to our new social network!'))
    c.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
              (2, 'Hello everyone, happy to be here!'))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'username' in session:
        conn = sqlite3.connect('social_network.db')
        c = conn.cursor()
        # Fetch posts to display in the feed
        c.execute('''
            SELECT posts.content, posts.timestamp, users.username
            FROM posts
            JOIN users ON posts.user_id = users.id
            ORDER BY posts.timestamp DESC
        ''')
        posts = c.fetchall()
        conn.close()
        # Render the feed with the posts
        return render_template_string('''
            <html>
            <head>
                <title>SocialNet - Home</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                    .container { width: 50%; margin: 0 auto; }
                    .post { background-color: #fff; padding: 15px; margin-top: 10px; border-radius: 5px; }
                    .post h3 { margin: 0; }
                    .post p { margin: 5px 0; }
                    .logout { float: right; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome, {{ username }}! <a href="{{ url_for('logout') }}" class="logout">Logout</a></h1>
                    {% for post in posts %}
                        <div class="post">
                            <h3>{{ post[2] }}</h3>
                            <small>{{ post[1] }}</small>
                            <p>{{ post[0] }}</p>
                        </div>
                    {% endfor %}
                </div>
            </body>
            </html>
        ''', username=session['username'], posts=posts)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        # Retrieve form input
        username = request.form['username']
        password = request.form['password']

        # Flawed input sanitization attempt
        username = username.replace("'", "''")
        password = password.replace("'", "''")

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('social_network.db')
        c = conn.cursor()

        # Intentionally vulnerable SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            if user:
                session['username'] = user[1]
                return redirect(url_for('index'))
            else:
                error = 'Invalid credentials. Please try again.'
        except Exception as e:
            error = 'An error occurred during login.'
        conn.close()

    # Render the login page
    return render_template_string('''
        <html>
        <head>
            <title>SocialNet - Login</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                .login-container { width: 300px; margin: 100px auto; background-color: #fff; padding: 20px; border-radius: 5px; }
                h1 { text-align: center; }
                input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
                input[type=submit] { width: 100%; padding: 10px; background-color: #4285F4; color: #fff; border: none; border-radius: 5px; }
                .error { color: red; text-align: center; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>SocialNet Login</h1>
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required><br>
                    <input type="password" name="password" placeholder="Password" required><br>
                    <input type="submit" value="Login">
                </form>
                {% if error %}
                    <p class="error">{{ error }}</p>
                {% endif %}
            </div>
        </body>
        </html>
    ''', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Initialize the d)