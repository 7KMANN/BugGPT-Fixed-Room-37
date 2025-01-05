from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated database of users and bookings
users = {
    'alice': {
        'password': hashlib.sha256(b'alicepassword').hexdigest(),
        'bookings': [
            {'id': 1, 'destination': 'Paris', 'date': '2023-11-15', 'details': 'Flight AC123, Hotel Le Meurice'},
            {'id': 2, 'destination': 'Tokyo', 'date': '2024-01-10', 'details': 'Flight JL456, Hotel Park Hyatt'},
        ],
    },
    'bob': {
        'password': hashlib.sha256(b'bobpassword').hexdigest(),
        'bookings': [
            {'id': 3, 'destination': 'New York', 'date': '2023-12-20', 'details': 'Flight DL789, Hotel The Plaza'},
            {'id': 4, 'destination': 'London', 'date': '2024-02-14', 'details': 'Flight BA012, Hotel The Savoy'},
        ],
    },
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            next_url = request.url
            return redirect(url_for('login', next=next_url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    username = session['username']
    user = users[username]
    bookings = user['bookings']
    return render_template_string(home_template, bookings=bookings, username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or url_for('home')
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        user = users.get(username)
        if user and user['password'] == hashed_pw:
            session['username'] = username
            return redirect(next_url)
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string(login_template, error=error, next_url=next_url)

@app.route('/booking/<int:booking_id>')
@login_required
def booking(booking_id):
    # Vulnerability: IDOR
    # Booking is retrieved without verifying ownership
    all_bookings = []
    for u in users.values():
        all_bookings.extend(u['bookings'])
    booking = next((b for b in all_bookings if b['id'] == booking_id), None)
    if booking is None:
        return 'Booking not found', 404
    return render_template_string(booking_template, booking=booking, username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Templates
login_template = """
<!DOCTYPE html>
<html>
<head>
    <title>BookIt - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        .container { width: 300px; margin: 0 auto; padding-top: 100px; }
        h1 { text-align: center; }
        form { background-color: #fff; padding: 20px; border-radius: 5px; }
        label { display: block; margin-top: 10px; }
        input { width: 100%; padding: 8px; margin-top: 5px; }
        .btn { background-color: #4CAF50; color: white; padding: 10px; margin-top: 15px; width: 100%; border: none; cursor: pointer; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to BookIt</h1>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post" action="{{ url_for('login') }}">
            <input type="hidden" name="next" value="{{ next_url }}">
            <label for="username">Username:</label>
            <input type="text" name="username" id="username" required/>
            <label for="password">Password:</label>
            <input type="password" name="password" id="password" required/>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
</body>
</html>
"""

home_template = """
<!DOCTYPE html>
<html>
<head>
    <title>BookIt - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e0f7fa; }
        .container { width: 800px; margin: 0 auto; padding-top: 50px; }
        h1, h2 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 30px; }
        th, td { border: 1px solid #00796b; padding: 12px; text-align: center; }
        th { background-color: #004d40; color: white; }
        tr:nth-child(even) { background-color: #b2dfdb; }
        a { text-decoration: none; color: #00796b; }
        .logout { text-align: right; }
        .logout a { color: #d32f2f; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logout">
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        <h1>Welcome, {{ username }}!</h1>
        <h2>Your Upcoming Trips</h2>
        <table>
            <tr>
                <th>Destination</th>
                <th>Date</th>
                <th>Details</th>
            </tr>
            {% for booking in bookings %}
            <tr>
                <td><a href="{{ url_for('booking', booking_id=booking['id']) }}">{{ booking['destination'] }}</a></td>
                <td>{{ booking['date'] }}</td>
                <td>{{ booking['details'] }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
"""

booking_template = """
<!DOCTYPE html>
<html>
<head>
    <title>BookIt - Booking Details</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff3e0; }
        .container { width: 600px; margin: 0 auto; padding-top: 50px; }
        h1 { text-align: center; }
        .details { background-color: #ffe0b2; padding: 20px; border-radius: 5px; }
        p { font-size: 18px; }
        a { display: inline-block; margin-top: 20px; color: #e64a19; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Booking Details</h1>
        <div class="details">
            <p><strong>Destination:</strong> {{ booking['destination'] }}</p>
            <p><strong>Date:</strong> {{ booking['date'] }}</p>
            <p><strong>Details:</strong> {{ booking['details'] }}</p>
        </div>
        <a href="{{ url_for('home') }}">Back to Dashboard</a>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True)