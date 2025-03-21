#!/usr/bin/env python3
"""
This script generates a HTML formatted email with text and table after reading warning logs
before sending email
"""
import health_check 
import email.message
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def generate_html_email(sender, recipient, subject, log_data):
    """Generates an HTML email with a table from log data."""

    message = MIMEMultipart("alternative")
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject

    # Create the HTML table
    html_table = "<table><tr><th>Case</th><th>Subject line</th></tr>"
    
    # CPU logs
    for log in cpu_logs:
        html_table += f"<tr><td>CPU usage is over 80%</td><td>{log}</td></tr>"

    # Disk logs
    for log in disk_logs:
        html_table += f"<tr><td>Available disk space is lower than 20%</td><td>{log}</td></tr>"

    # Memory logs
    for log in mem_logs:
        html_table += f"<tr><td>Available memory is less than 100MB</td><td>{log}</td></tr>"

    # Host logs
    for log in host_logs:
        html_table += f"<tr><td>hostname 'localhost' cannot be resolved to 127.0.0.1</td><td>{log}</td></tr>"

    html_table += "</table>"

    # Create the HTML part
    html_part = MIMEText(f"""
    <html>
      <head></head>
      <body>
        {html_table}
        <p>Please check your system and resolve the issue as soon as possible.</p>
      </body>
    </html>
    """, "html")

    # Attach the HTML part
    message.attach(html_part)

    return message

def send_email(message):
    """Sends the message to the configured SMTP server."""
    try:
        mail_server = smtplib.SMTP('localhost')
        mail_server.send_message(message)
        mail_server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")