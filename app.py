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
import logging

app = Flask(__name__)

app.secret_key = 'super_secure_key'
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are transmitted securely
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevents CSRF in cross-site contexts
Session(app)

# Configure logging
logging.basicConfig(
    filename='app.log',  # Log file name
    level=logging.INFO,  # Logging level
    format='%(asctime)s - %(levelname)s - %(message)s'
)


@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://kit.fontawesome.com https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-src 'self' https://www.google.com https://www.gstatic.com; "
        "frame-ancestors 'none';")
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    return response


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
    user_ip = request.remote_addr
    logging.info(f"Sign-in page accessed. IP: {user_ip}")
    return render_template('signin.html');

@app.route('/signout')
def signout():
    user_ip = request.remote_addr
    logging.info(f"Sign-out. IP: {user_ip}")
    session.pop('user', None)
    return redirect("/")



@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit requests to 5 per minute
def signup():
    user_ip = request.remote_addr  # Get client IP address
    if request.method == 'GET':
        logging.info(f"Sign-up page accessed. IP: {user_ip}")
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
            logging.info(f"User registered successfully. Email: {cleanEmail}, IP: {user_ip}")
            
            return render_template('signin.html', message="User registered successfully. Please sign in.")
        
        except sqlite3.Error as e:
            logging.error(f"Database error during sign-up. IP: {user_ip}, Error: {e}")
            return render_template('error.html', error="Database error")
        
        finally:
            # Close the database connection
            conn.close()
    
    

@app.route('/signin', methods=['POST'])
@limiter.limit("10 per minute")  # Rate limit for this specific route
def signin():
    user_ip = request.remote_addr  # Get client IP address
    email = request.form['email']
    password = request.form['password']

    # Input validation for XSS
    if check_xss_input(email) or check_xss_input(password):
        logging.warning(f"XSS detected during sign-in. IP: {user_ip}")
        return render_template('error.html', error="XSS detected")

    # Input validation for SQL Injection
    if check_sql_injection(email) or check_sql_injection(password):
        logging.warning(f"SQL Injection detected during sign-in. IP: {user_ip}")
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
            logging.info(f"User login successful. Email: {email}, IP: {user_ip}")
            session['user'] = email
            return render_template('site.html', user=email, password=password)  # Redirect to the main page
        else:
            logging.warning(f"Invalid login attempt. Email: {email}, IP: {user_ip}")
            return render_template('error.html', error="Invalid credentials")

    except sqlite3.Error as e:
        logging.error(f"Database error during sign-in. IP: {user_ip}, Error: {e}")
        return render_template('error.html', error="Database error")

    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    app.run(debug=True)
    
