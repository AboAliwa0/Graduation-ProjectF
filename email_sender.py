import smtplib
from email.mime.text import MIMEText

EMAIL = "ibrahim4hema20@gmail.com"
PASSWORD = "fphq kwfw pemp uook"


def send_otp(receiver_email, otp):
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

    except Exception as e:
        print("Error sending email:", e)