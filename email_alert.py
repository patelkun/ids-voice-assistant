import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("APP_PASSWORD")

def send_alert(ip, attack_type):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL
        msg["To"] = EMAIL
        msg["Subject"] = f"🚨 IDS Alert — {attack_type} Detected!"

        body = f"""
        IDS Security Alert!
        
        Attack Type: {attack_type}
        Suspicious IP: {ip}
        
        Turant action lo!
        
        — AI IDS System
        """

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, EMAIL, msg.as_string())
        server.quit()

        print(f"Email sent! Attack: {attack_type} from {ip}")
        return True

    except Exception as e:
        print(f"Email error: {e}")
        return False

# Test karo
print("Email test kar raha hoon...")
result = send_alert("192.168.1.100", "ping_flood")
if result:
    print("Email aa gaya!")
else:
    print("Email nahi aaya — error check karo")