from flask import Flask, render_template, request, url_for,redirect
import re
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, session
from flask_session import Session
import html 
from bcrypt import hashpw, gensalt, checkpw  # Import bcrypt functions
import bleach

app = Flask(__name__)

app.secret_key = 'super_secure_key'
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are transmitted securely
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
Session(app)


# Initialize Limiter with the app
limiter = Limiter(
    get_remote_address,  # Uses IP address to identify the requester
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Global rate limits
)

def check_xss_input(user_input: str) -> bool:
    """
    Check if the input contains potential cross-site scripting (XSS) patterns.

    Args:
        user_input (str): The input string to validate.

    Returns:
        bool: True if XSS patterns are detected, False otherwise.
    """
    # List of suspicious patterns to look for
    xss_patterns = [
        r"<script.*?>.*?</script.*?>",  # Detect <script> tags
        r"javascript:",                 # Detect 'javascript:' protocol
        r"<.*?on\w+.*?=.*?>",          # Detect inline event handlers (onload, onclick, etc.)
        r"<iframe.*?>.*?</iframe.*?>",  # Detect iframe tags
        r"<object.*?>.*?</object.*?>",  # Detect object tags
        r"<embed.*?>.*?</embed.*?>",    # Detect embed tags
        r"<applet.*?>.*?</applet.*?>",  # Detect applet tags
        r"<meta.*?>",                   # Detect meta tags
        r"<img.*?src=.*?>",             # Detect img tags with suspicious attributes
        r"\b(alert|prompt|confirm)\b", # Detect JavaScript functions
    ]

    # Combine all patterns into a single regex
    combined_pattern = re.compile("|".join(xss_patterns), re.IGNORECASE | re.DOTALL)

    # Search for XSS patterns in the input
    if re.search(combined_pattern, user_input):
        print("XSS detected")
        return True  # XSS detected
    return False  # No XSS detected   


def check_sql_injection(user_input: str) -> bool:
    """
    Check if the input contains potential SQL injection patterns.

    Args:
        user_input (str): The input string to validate.

    Returns:
        bool: True if SQL injection patterns are detected, False otherwise.
    """
    # List of suspicious patterns to look for
    sql_patterns = [
        r"(--|#)",                    # SQL comment patterns
        r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|TRUNCATE)\b",  # SQL keywords
        r"('|\"|\bNULL\b)",           # Unescaped quotes or NULL
        r"\bOR\b.*?=.*?\bOR\b",  # 'OR' logic patterns
        r"(;\s*--)",                  # Query termination
    ]

    # Combine all patterns into a single regex
    combined_pattern = re.compile("|".join(sql_patterns), re.IGNORECASE)

    # Search for SQL patterns in the input
    if re.search(combined_pattern, user_input):
        return True  # SQL injection detected
    return False  # No SQL injection detected


@app.route('/')
def hello_world():
    return render_template('signin.html');

@app.route('/signout')
def signout():
    session.pop('user', None)
    return redirect("/")



@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit requests to 5 per minute
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Sanitize inputs with bleach
        cleanUsername = bleach.clean(username.strip(), tags=[], attributes={}, styles=[])
        cleanEmail = bleach.clean(email.strip(), tags=[], attributes={}, styles=[])
        cleanPassword = bleach.clean(password.strip(), tags=[], attributes={}, styles=[])

        try:
            # Hash the password using bcrypt
            hashedPassword = hashpw(cleanPassword.encode('utf-8'), gensalt())
            
            # Connect to the database
            conn = sqlite3.connect('login.db')
            cursor = conn.cursor()
            
            # Check if the email already exists in the database
            query = "SELECT * FROM users WHERE email = ?"
            cursor.execute(query, (cleanEmail,))
            user = cursor.fetchone()
            if user is not None:
                print("User already exists:", cleanEmail)
                return render_template('error.html', error="User already exists")
            
            # Insert the new user into the database with the hashed password
            query = "INSERT INTO users (email, password) VALUES (?, ?)"
            cursor.execute(query, (cleanEmail, hashedPassword))
            conn.commit()
            print("User registered:", cleanEmail)
            
            return render_template('signin.html', message="User registered successfully. Please sign in.")
        
        except sqlite3.Error as e:
            print("Database error:", e)
            return render_template('error.html', error="Database error")
        
        finally:
            # Close the database connection
            conn.close()
    
    

@app.route('/signin', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit for this specific route
def signin():
    email = request.form['email']
    password = request.form['password']

    # Input validation for XSS
    if check_xss_input(email) or check_xss_input(password):
        print("XSS detected.")
        return render_template('error.html', error="XSS detected")

    # Input validation for SQL Injection
    if check_sql_injection(email) or check_sql_injection(password):
        print("SQL Injection detected.")
        return render_template('error.html', error="SQL Injection detected")

    # Connect to the SQLite database
    try:
        conn = sqlite3.connect('login.db')
        cursor = conn.cursor()
        
        # Use parameterized queries to avoid SQL Injection
        query = "SELECT * FROM users WHERE email = ? AND password = ?"
        cursor.execute(query, (email, password))
        user = cursor.fetchone()  # Fetch a single matching user

        if user:
            print("Login successful for:", email)
            session['user'] = email
            return render_template('site.html', user=email, password=password)  # Redirect to the main page
        else:
            print("Invalid credentials for:", email)
            return render_template('error.html', error="Invalid credentials")

    except sqlite3.Error as e:
        print("Database error:", e)
        return render_template('error.html', error="Database error")

    finally:
        cursor.close()
        conn.close()


# @app.route('/error/<string:error>')
# def error():
#     return render_template('error.html', error=error);

if __name__ == '__main__':
    app.run(debug=True)
    
