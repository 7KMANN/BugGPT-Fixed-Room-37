from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

def sanitize_input(user_input):
    # Sanitize input to prevent XSS attacks
    # Remove <script> tags
    sanitized = re.sub(r'<\s*/*\s*script\s*>', '', user_input, flags=re.IGNORECASE)
    # Remove JavaScript event handlers (e.g., onclick, onerror)
    sanitized = re.sub(r'on\w+\s*=\s*"[^"]*"', '', sanitized)
    # Remove JavaScript protocol
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    # Encode angle brackets
    sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
    return sanitized

@app.route('/', methods=['GET', 'POST'])
def index():
    search_query = ''
    if request.method == 'POST':
        search_query = request.form.get('search', '')
        search_query = sanitize_input(search_query)
    return render_template_string('''
<!doctype html>
<html lang="en">
<head>
    <title>National Government Services Portal</title>
    <style>
        /* General Styles */
        body {
            font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        /* Header */
        header {
            background-color: #002868;
            color: white;
            padding: 20px;
        }
        header h1 {
            margin: 0;
            font-size: 2em;
        }
        nav {
            margin-top: 10px;
        }
        nav a {
            color: white;
            margin-right: 20px;
            text-decoration: none;
            font-weight: bold;
        }
        /* Main Content */
        main {
            padding: 20px;
            background-color: white;
        }
        main h2 {
            color: #002868;
        }
        main p {
            font-size: 1.1em;
        }
        /* Search Form */
        .search-form {
            margin-top: 30px;
        }
        .search-form input[type="text"] {
            width: 300px;
            padding: 10px;
            font-size: 1em;
        }
        .search-form button {
            padding: 10px 20px;
            font-size: 1em;
            background-color: #205493;
            color: white;
            border: none;
            cursor: pointer;
        }
        /* Search Results */
        .search-results {
            margin-top: 40px;
        }
        .search-results h3 {
            color: #205493;
        }
        /* Footer */
        footer {
            background-color: #e4e5e7;
            color: #333;
            text-align: center;
            padding: 15px;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
        /* Responsive */
        @media (max-width: 600px) {
            .search-form input[type="text"] {
                width: 100%;
            }
            nav a {
                display: block;
                margin-bottom: 10px;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>National Government Services Portal</h1>
        <nav>
            <a href="/">Home</a>
            <a href="#">Services</a>
            <a href="#">Departments</a>
            <a href="#">About Us</a>
            <a href="#">Contact</a>
        </nav>
    </header>
    <main>
        <h2>Welcome to Your Gateway of Government Services</h2>
        <p>Connecting citizens with a comprehensive range of government services and information.</p>
        <div class="search-form">
            <form method="post">
                <input type="text" name="search" placeholder="Search for services..." required>
                <button type="submit">Search</button>
            </form>
        </div>
        {% if search_query %}
            <div class="search-results">
                <h3>Search Results for "{{ search_query }}"</h3>
                <p>Sorry, no results were found matching your query.</p>
            </div>
        {% endif %}
    </main>
    <footer>
        <p>&copy; 2023 National Government. All rights reserved.</p>
    </footer>
</body>
</html>
''', search_query=search_query)

if __name__ == '__main__':
    app.run(debug=True)