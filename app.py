import pyotp
import qrcode
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for sessions

# Global variables for rate limiting
last_request_time = 0
rate_limit_seconds = 30  # Set the rate limit to 30 seconds

def generate_otp():
    """Generate a simple OTP and return it."""
    secret = pyotp.random_base32()
    return secret

def generate_totp():
    """Generate a TOTP and return the secret and OTP."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    return secret, otp

def generate_qr_code(secret):
    """Generate a QR code for the TOTP secret."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri("MyAppName", issuer_name="MyCompany")
    img = qrcode.make(uri)
    img.save("otp_qr_code.png")
    return "otp_qr_code.png"  # Return QR code file name for user to download

# Rate limiting function
def rate_limit():
    global last_request_time
    current_time = time.time()
    if current_time - last_request_time < rate_limit_seconds:
        remaining_time = rate_limit_seconds - (current_time - last_request_time)
        return False, remaining_time
    last_request_time = current_time
    return True, 0

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/generate_otp', methods=['POST'])
def generate():
    success, remaining_time = rate_limit()
    if not success:
        flash(f"Rate limit exceeded. Please wait {int(remaining_time)} seconds.")
        return redirect(url_for('home'))

    otp = generate_otp()  # Generate basic OTP
    session['otp'] = otp  # Store OTP in session for demo
    flash("OTP sent! Please check your email or SMS.")
    return redirect(url_for('home'))

@app.route('/verify_otp', methods=['POST'])
def verify():
    user_otp = request.form['otp']  # Get OTP entered by the user
    if 'otp' in session:
        if user_otp == session['otp']:  # Compare OTP entered with the stored one
            flash("✅ OTP verified successfully!")
        else:
            flash("❌ Incorrect OTP. Please try again.")
    else:
        flash("❌ No OTP generated. Please generate an OTP first.")
    return redirect(url_for('home'))

@app.route('/generate_totp', methods=['POST'])
def generate_totp_route():
    success, remaining_time = rate_limit()
    if not success:
        flash(f"Rate limit exceeded. Please wait {int(remaining_time)} seconds.")
        return redirect(url_for('home'))

    secret, otp = generate_totp()  # Generate TOTP
    session['totp_secret'] = secret  # Store TOTP secret in session for verification
    flash(f"TOTP generated! Your TOTP is: {otp}")
    return redirect(url_for('home'))

@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    user_totp = request.form['otp']  # Get TOTP entered by the user
    if 'totp_secret' in session:
        totp = pyotp.TOTP(session['totp_secret'])
        if totp.verify(user_totp):  # Verify the entered TOTP
            flash("✅ TOTP verified successfully!")
        else:
            flash("❌ Incorrect TOTP. Please try again.")
    else:
        flash("❌ No TOTP generated. Please generate a TOTP first.")
    return redirect(url_for('home'))

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    success, remaining_time = rate_limit()
    if not success:
        flash(f"Rate limit exceeded. Please wait {int(remaining_time)} seconds.")
        return redirect(url_for('home'))

    if 'totp_secret' in session:
        secret = session['totp_secret']
        qr_image = generate_qr_code(secret)
        flash("QR Code generated successfully!")
        return redirect(url_for('home'))
    else:
        flash("❌ No TOTP secret found. Please generate a TOTP first.")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
