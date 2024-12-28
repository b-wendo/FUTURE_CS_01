import base64
import bcrypt
import os
import pyotp
import qrcode
import sqlite3
import validators
from dotenv import load_dotenv
from io import BytesIO
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    get_flashed_messages,
)

load_dotenv()  # This loads the .env file variables

app = Flask(__name__)

# Load secret key from environment variable
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret_key")


def create_tables():
    """Creates the 'users' table in the SQLite database."""
    conn = sqlite3.connect("2FA.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()


def generate_qr_code(secret):
    """Generate a QR code for the TOTP secret (Time-based One-Time Password)."""
    totp = pyotp.TOTP(secret)  # Create a TOTP object using the user's secret
    uri = totp.provisioning_uri(
        "MyAppName", issuer_name="MyCompany"
    )  # Generate a URI for the QR code
    img = qrcode.make(uri)  # Generate the QR code based on the URI
    img_io = BytesIO()  # Store the image in memory instead of a file
    img.save(img_io, format="PNG")  # Save the image in PNG format
    img_bytes = img_io.getvalue()  # Convert the image to bytes
    img_base64 = base64.b64encode(img_bytes).decode(
        "utf-8"
    )  # Encode the image to base64 to embed it in HTML
    return img_base64  # Return the base64 encoded QR code


def is_valid_email(email):
    return validators.email(email)


def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.islower() for char in password):
        return False, "Password must include at least one lowercase letter."
    if not any(char.isupper() for char in password):
        return False, "Password must include at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must include at least one digit."
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        return False, "Password must include at least one special character."
    return True, "Password is valid."


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get user input from the form
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validate email format
        if not is_valid_email(email):
            flash("Invalid email address. Please provide a valid email.")
            return render_template("register.html")

        # Validate password complexity
        is_valid, message = is_valid_password(password)
        if not is_valid:
            flash(message)  # Show specific password validation error
            return render_template("register.html")

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match. Please try again.")
            return render_template("register.html")

        # Continue with registration process
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        )
        secret = pyotp.random_base32()  # Generate a random base32 secret for 2FA

        try:
            # Insert new user into the database
            connection = sqlite3.connect("2FA.db")
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO users (username, email, hashed_password, secret)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, hashed_password, secret),
            )
            connection.commit()
            flash("Account successfully created")
            session["username"] = username  # Store username in session
            return redirect(url_for("setup_2fa"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists. Please try a different one.")
        except Exception as e:
            flash("An error occurred during registration.")
            print(f"Error: {e}")
        finally:
            connection.close()
    return render_template("register.html")


@app.route("/setup_2fa")
def setup_2fa():
    # Consume any residual flash messages
    get_flashed_messages()

    if "username" in session:
        try:
            conn = sqlite3.connect("2FA.db")
            cursor = conn.cursor()

            cursor.execute(
                "SELECT secret FROM users WHERE username=?", (session["username"],)
            )
            result = cursor.fetchone()

            if result:
                totp_secret = result[0]
                totp = pyotp.TOTP(totp_secret)
                uri = totp.provisioning_uri(
                    session["username"], issuer_name="MyAppName"
                )

                # Store totp_secret in session for later verification
                session["totp_secret"] = totp_secret

                img = qrcode.make(uri)
                img_io = BytesIO()
                img.save(img_io, format="PNG")
                img_bytes = img_io.getvalue()
                img_base64 = base64.b64encode(img_bytes).decode("utf-8")
                flash("Account created successfully! Please verify 2FA.")

                return render_template(
                    "setup_2fa.html", uri=uri, qr_code_image=img_base64
                )

            else:
                flash("Error retrieving user data.")
                return redirect(url_for("home"))

        except Exception as e:
            flash(f"An error occurred: {e}")
            return redirect(url_for("home"))
        finally:
            conn.close()

    else:
        flash("Please log in to set up 2FA.")
        return redirect(url_for("login"))


@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "POST":
        user_totp = request.form["totp"]  # Get the TOTP entered by the user

        # Check if we have the TOTP secret in session
        if "totp_secret" in session:
            totp = pyotp.TOTP(
                session["totp_secret"]
            )  # Create a TOTP object with the stored secret
            if totp.verify(
                user_totp
            ):  # Verify the user's entered TOTP against the secret
                session["logged_in"] = True  # Mark the user as logged in
                flash("2FA verified successfully! You are now logged in.")
                return redirect(url_for("dashboard"))
            else:
                flash(
                    "Incorrect TOTP code. Please try again."
                )  # Show error if TOTP doesn't match
        else:
            flash("An error occurred during 2FA verification. Please log in again.")
            return redirect(url_for("login"))

    return render_template("verify_2fa.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "logged_in" in session and session["logged_in"]:
        return redirect(
            url_for("dashboard")
        )  # Redirect to dashboard for logged-in users

    if request.method == "POST":
        login_id = request.form["login_id"]  # This can be either username or email
        password = request.form["password"]

        try:
            # Connect to SQLite database to check if user exists or insert a new user
            connection = sqlite3.connect("2FA.db")
            cursor = connection.cursor()

            # Check if login_id is an email or username
            cursor.execute(
                "SELECT username, email, hashed_password, secret FROM users WHERE username = ? OR email = ?",
                (login_id, login_id),
            )
            user = cursor.fetchone()

            if user:
                username = user[0]
                email = user[1]
                hashed_password = user[2]
                totp_secret = user[3]

                # Verify password
                if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
                    session["logged_in"] = True
                    session["username"] = username
                    session["email"] = email
                    session["totp_secret"] = totp_secret
                    return redirect(
                        url_for("verify_2fa")
                    )  # Redirect to 2FA verification page
                else:
                    flash("Incorrect password.")
            else:
                flash("Invalid username or email.")
        except Exception as e:
            flash("An error occurred during login.")
            print(f"Database Error: {e}")
        finally:
            connection.close()

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    # Check if the 'username' is in the session, meaning the user is logged in
    if "username" in session:
        # If the user is logged in, render the 'dashboard.html' template and pass in the user's data
        # 'username' will be displayed on the dashboard, and flags for account creation and 2FA verification are set to True
        return render_template(
            "dashboard.html",
            username=session[
                "username"
            ],  # Pass the logged-in user's username to the template
            account_created=True,  # Flag indicating that the account has been successfully created
            twofa_verified=True,  # Flag indicating that the user has completed 2FA setup and verification
        )
    else:
        # If the 'username' is not in the session, meaning the user is not logged in,
        # redirect them to the login page and show a flash message
        flash("Please log in to access the dashboard.")
        return redirect(url_for("login"))  # Redirect the user to the login page


@app.route("/logout")
def logout():
    # Clear all session data, effectively logging the user out
    session.clear()  # Clears the session, removing any stored user information such as 'username' and 'logged_in' status

    # Flash a message to let the user know they have been logged out
    flash(
        "You have been logged out."
    )  # This message will be shown on the next page, confirming the logout

    # Redirect the user to the login page
    return redirect(
        url_for("login")
    )  # After logging out, the user is redirected to the login page


if __name__ == "__main__":
    create_tables()  # Ensure this is called before running the app
    app.run(debug=True)
