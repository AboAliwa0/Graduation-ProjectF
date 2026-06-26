import smtplib
import os
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

EMAIL = os.getenv("EMAIL_SENDER")
PASSWORD = os.getenv("EMAIL_APP_PASSWORD")


def send_otp(receiver_email, otp):
    if not EMAIL or not PASSWORD:
        print("Email credentials are not configured")
        return False

    subject = "Your OTP Code"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL, PASSWORD)
            server.sendmail(EMAIL, receiver_email, msg.as_string())

        print("OTP sent successfully")
        return True

    except Exception as e:
        print("Error sending email:", e)
        return False
