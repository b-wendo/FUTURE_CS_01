import pyotp
import qrcode
import time
from flask import session

# Declare global variables for rate-limiting (if you're using Flask sessions)
rate_limit_seconds = 30  # Set the rate limit to 30 seconds

# Function to generate a basic OTP (6 digits)
def generate_otp():
    otp = str(pyotp.random_base32()[:6])  # Generate a simple 6-character OTP
    return otp

# Function to verify the OTP entered by the user
def verify_otp(entered_otp, stored_otp):
    if entered_otp == stored_otp:
        return True
    else:
        return False

# Rate limiting function (using Flask's session)
def rate_limit(session):
    current_time = time.time()
    
    # Initialize attempts if not present in the session
    if 'attempts' not in session:
        session['attempts'] = 0
        session['last_attempt_time'] = current_time

    # Get the time difference since the last attempt
    time_since_last_attempt = current_time - session['last_attempt_time']

    if time_since_last_attempt > rate_limit_seconds:  # If more than rate_limit_seconds have passed, reset
        session['attempts'] = 0
        session['last_attempt_time'] = current_time

    if session['attempts'] >= 3:  # If there have been more than 3 attempts within the rate-limiting time frame
        return False  # Too many attempts, rate-limited
    else:
        session['attempts'] += 1
        return True  # User can make another attempt

# Function to generate a QR code for TOTP (Time-based OTP)
def generate_qr_code(secret):
    totp = pyotp.TOTP(secret)

    # Generate the provisioning URI for the QR code
    uri = totp.provisioning_uri("MyAppName", issuer_name="MyCompany")

    # Create a QR code from the URI
    img = qrcode.make(uri)

    # Save the QR code as an image file
    img.save("otp_qr_code.png")

    # Print and display the message that the code has been saved
    print("QR Code generated and saved as 'otp_qr_code.png'.")

