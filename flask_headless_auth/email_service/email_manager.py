"""
flask_headless_auth.email_service.email_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Email manager that abstracts email service providers.
"""

from urllib.parse import urljoin
from flask import current_app
from flask_headless_auth.email_service.token import generate_confirmation_token
from flask_headless_auth.email_service.gmail_service import GmailService
from flask_headless_auth.email_service.brevo_service import BrevoService


class EmailManager:
    """Email infrastructure manager - handles email sending via different providers."""
    
    def __init__(self, service_name: str, config: dict):
        """
        Initialize email manager with specified service.
        
        Args:
            service_name: 'gmail' or 'brevo'
            config: Flask app config dict
        """
        if service_name == 'gmail':
            self.service = GmailService(
                smtp_server=config.get('MAIL_SERVER', 'smtp.gmail.com'),
                smtp_port=config.get('MAIL_PORT', 587),
                username=config['MAIL_USERNAME'],
                password=config['MAIL_PASSWORD']
            )
        elif service_name == 'brevo':
            brevo_key = config.get('BREVO_API_KEY')
            if not brevo_key:
                raise ValueError("BREVO_API_KEY is required for Brevo service but not found in config")
            
            sender_email = config.get('BREVO_SENDER_EMAIL', 'noreply@example.com')
            sender_name = config.get('BREVO_SENDER_NAME', 'Auth Service')
            
            self.service = BrevoService(
                api_key=brevo_key,
                sender_email=sender_email,
                sender_name=sender_name
            )
        else:
            raise ValueError(f"Unsupported email service: {service_name}. Use 'gmail' or 'brevo'.")

    def send_verification_email(self, recipient_email: str):
        """
        Send a verification email to the user.
        
        Args:
            recipient_email: Email address to send verification to
            
        Returns:
            bool: True if email sent successfully
        """
        # Generate email verification token
        token = generate_confirmation_token(recipient_email)
        
        # Use the frontend URL from config to create the verification URL
        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        verification_url = urljoin(frontend_url, f'/confirm-email?token={token}')
        
        return self.service.send_verification_email(recipient_email, verification_url)
    
    def send_templated_email(self, recipient_email: str, subject: str, html_content: str, sender_name: str = None):
        """Send a templated HTML email."""
        return self.service.send_templated_email(recipient_email, subject, html_content, sender_name)
    
    def send_simple_email(self, recipient_email: str, subject: str, plain_text: str, sender_name: str = None):
        """Send a simple plain text email."""
        return self.service.send_simple_email(recipient_email, subject, plain_text, sender_name)

