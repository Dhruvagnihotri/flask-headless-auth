"""
flask_headless_auth.email_service.gmail_service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gmail SMTP email service implementation.
"""

from flask_headless_auth.email_service.email_service import EmailService
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class GmailService(EmailService):
    """Concrete implementation of EmailService using Gmail SMTP."""

    def __init__(self, smtp_server, smtp_port, username, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password

    def send_verification_email(self, recipient_email: str, verification_url: str):
        """Send a verification email via Gmail SMTP."""
        subject = "Verify Your Email Address"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Email Verification</h2>
                <p>Thank you for registering! Please verify your email address by clicking the button below:</p>
                <p style="margin: 30px 0;">
                    <a href="{verification_url}" 
                       style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 4px; display: inline-block;">
                        Verify Email
                    </a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p style="color: #666; word-break: break-all;">{verification_url}</p>
                <p style="margin-top: 30px; color: #999; font-size: 12px;">
                    This link will expire in 48 hours. If you didn't request this verification, please ignore this email.
                </p>
            </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = recipient_email
        
        # Plain text fallback
        text_part = MIMEText(f'Click the link to verify your email: {verification_url}', 'plain')
        html_part = MIMEText(html_body, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, recipient_email, msg.as_string())
            print(f"✅ Verification email sent to {recipient_email} via Gmail")
            return True
        except Exception as e:
            print(f"❌ Failed to send email via Gmail: {str(e)}")
            return False

    def send_templated_email(self, recipient_email: str, subject: str, html_content: str, sender_name: str = None):
        """Send a templated HTML email via Gmail SMTP."""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_name if sender_name else self.username
        msg['To'] = recipient_email
        
        # Convert HTML to plain text for fallback
        import re
        text_content = re.sub('<[^<]+?>', '', html_content)
        
        text_part = MIMEText(text_content, 'plain')
        html_part = MIMEText(html_content, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, recipient_email, msg.as_string())
            print(f"✅ Templated email sent to {recipient_email} via Gmail")
            return True
        except Exception as e:
            print(f"❌ Failed to send templated email via Gmail: {str(e)}")
            return False

    def send_simple_email(self, recipient_email: str, subject: str, plain_text: str, sender_name: str = None):
        """Send a simple plain text email via Gmail SMTP."""
        msg = MIMEText(plain_text)
        msg['Subject'] = subject
        msg['From'] = sender_name if sender_name else self.username
        msg['To'] = recipient_email

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, recipient_email, msg.as_string())
            print(f"✅ Simple email sent to {recipient_email} via Gmail")
            return True
        except Exception as e:
            print(f"❌ Failed to send simple email via Gmail: {str(e)}")
            return False

