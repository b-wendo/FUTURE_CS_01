import pyotp
import qrcode
import time
import bcrypt
import sqlite3
import base64
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
# Load secret key from environment variable (recommended)
app.secret_key = ('your_secret_key')

# Global variables for rate limiting
last_request_time = 0
rate_limit_seconds = 30  # Set the rate limit to 30 seconds

def generate_qr_code(secret):
    """Generate a QR code for the TOTP secret."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri("MyAppName", issuer_name="MyCompany")
    img = qrcode.make(uri)
    img_io = BytesIO()
    img.save(img_io, format='PNG')
    img_bytes = img_io.getvalue()
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
    return img_base64  # Return base64 encoded QR code data

def rate_limit():
    """
    Implements rate limiting to prevent excessive login attempts.

    Returns:
        - (is_allowed, remaining_time):
            - is_allowed (bool): True if the request is allowed, False otherwise.
            - remaining_time (float): Time remaining until the next request is allowed (in seconds).
    """
    global last_request_time
    current_time = time.time()
    if current_time - last_request_time < rate_limit_seconds:
        remaining_time = rate_limit_seconds - (current_time - last_request_time)
        return False, remaining_time
    last_request_time = current_time
    return True, 0

def create_tables():
    """Creates the 'users' table in the SQLite database."""
    conn = sqlite3.connect('task1.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')  # Get the email
        password = request.form['password']

        # Rate limit check for registration
        is_allowed, remaining_time = rate_limit()
        if not is_allowed:
            flash(f"Too many registration attempts. Please try again in {remaining_time:.2f} seconds.")
            return render_template('register.html')

        if not username or not email:
            flash("Please enter both a username and email address.")
            return render_template('register.html')

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        # Generate TOTP secret
        secret = pyotp.random_base32()

        try:
            connection = sqlite3.connect('task1.db')
            cursor = connection.cursor()

            # Check if email already exists
            cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                flash("This email is already registered. Please use a different email address.")
                return render_template('register.html')

            # Insert user details into the database
            cursor.execute('''
                INSERT INTO users (username, email, hashed_password, secret)
                VALUES (?, ?, ?, ?)
            ''', (username, email, hashed_password, secret))
            connection.commit()
            session['username'] = username
            flash("Account created successfully! Please set up 2FA.")
            return redirect(url_for('setup_2fa'))
        except sqlite3.IntegrityError:
            flash("An error occurred during registration.")
        except Exception as e:
            flash("An unexpected error occurred.")
            print(f"Database Error: {e}")
        finally:
            connection.close()

    return render_template('register.html')



@app.route('/setup_2fa')
def setup_2fa():
    if 'username' in session:
        try:
            conn = sqlite3.connect('task1.db')
            cursor = conn.cursor()

            cursor.execute("SELECT secret FROM users WHERE username=?", (session['username'],))
            result = cursor.fetchone()

            if result:
                totp_secret = result[0]
                totp = pyotp.TOTP(totp_secret)
                uri = totp.provisioning_uri(session['username'], issuer_name="MyAppName")

                # Store totp_secret in session for later verification
                session['totp_secret'] = totp_secret 

                img = qrcode.make(uri)
                img_io = BytesIO()
                img.save(img_io, format='PNG')
                img_bytes = img_io.getvalue()
                img_base64 = base64.b64encode(img_bytes).decode('utf-8')

                return render_template('setup_2fa.html', uri=uri, qr_code_image=img_base64) 

            else:
                flash("Error retrieving user data.")
                return redirect(url_for('home'))

        except Exception as e:
            flash(f"An error occurred: {e}")
            return redirect(url_for('home')) 
        finally:
            conn.close()

    else:
        flash("Please log in to set up 2FA.")
        return redirect(url_for('login')) 
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_id = request.form['login_id']  # This can be either username or email
        password = request.form['password']

        # Check rate limit before processing login
        is_allowed, remaining_time = rate_limit()
        if not is_allowed:
            flash(f"Too many login attempts. Please try again in {remaining_time:.2f} seconds.")
            return render_template('login.html')

        try:
            connection = sqlite3.connect('task1.db')
            cursor = connection.cursor()

            # Check if login_id is an email or username
            cursor.execute("SELECT username, email, hashed_password, secret FROM users WHERE username = ? OR email = ?", (login_id, login_id))
            user = cursor.fetchone()

            if user:
                username = user[0]
                email = user[1]
                hashed_password = user[2]
                totp_secret = user[3]

                # Verify password
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    session['logged_in'] = True
                    session['username'] = username
                    session['email'] = email
                    session['totp_secret'] = totp_secret
                    return redirect(url_for('verify_2fa'))  # Redirect to 2FA verification page
                else:
                    flash("Incorrect password.")
            else:
                flash("Invalid username or email.")
        except Exception as e:
            flash("An error occurred during login.")
            print(f"Database Error: {e}")
        finally:
            connection.close()

    return render_template('login.html')


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        user_totp = request.form['totp']

        if 'totp_secret' in session:
            totp = pyotp.TOTP(session['totp_secret'])
            if totp.verify(user_totp):
                session['logged_in'] = True 
                flash("2FA verified successfully! You are now logged in.")
                return redirect(url_for('dashboard')) 
            else:
                flash("Incorrect TOTP code. Please try again.")
                return render_template('verify_2fa.html') 
        else:
            flash("An error occurred during 2FA verification.")
            return redirect(url_for('home')) 

    return render_template('verify_2fa.html') 

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template(
            'dashboard.html', 
            username=session['username'], 
            account_created=True, 
            twofa_verified=True
        )
    else:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_tables()  # Ensure this is called before running the app
    app.run(debug=True)

  