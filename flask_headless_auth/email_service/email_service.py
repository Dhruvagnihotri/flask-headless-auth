"""
flask_headless_auth.email_service.email_service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Abstract base class for email services.
"""

from abc import ABC, abstractmethod


class EmailService(ABC):
    """Abstract base class for email services - pure infrastructure layer."""
    
    @abstractmethod
    def send_verification_email(self, recipient_email: str, verification_url: str):
        """Send a verification email with a given token to the recipient."""
        pass
    
    @abstractmethod
    def send_templated_email(self, recipient_email: str, subject: str, html_content: str, sender_name: str = None):
        """Send a templated email with given subject and HTML content."""
        pass
    
    @abstractmethod
    def send_simple_email(self, recipient_email: str, subject: str, plain_text: str, sender_name: str = None):
        """Send a simple plain text email."""
        pass

