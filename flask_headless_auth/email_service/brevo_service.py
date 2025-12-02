"""
flask_headless_auth.email_service.brevo_service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Brevo (Sendinblue) API email service implementation.
"""

from flask_headless_auth.email_service.email_service import EmailService

try:
    import brevo_python
    from brevo_python.rest import ApiException
    BREVO_AVAILABLE = True
except ImportError:
    BREVO_AVAILABLE = False


class BrevoService(EmailService):
    """Concrete implementation of EmailService using Brevo (Sendinblue) API."""

    def __init__(self, api_key, sender_email='noreply@example.com', sender_name='Auth Service'):
        """Initialize Brevo service."""
        if not BREVO_AVAILABLE:
            raise ImportError(
                "brevo-python is required for Brevo email service. "
                "Install it with: pip install flask-headless-auth[email]"
            )
        
        self.configuration = brevo_python.Configuration()
        self.configuration.api_key['api-key'] = api_key
        self.api_instance = brevo_python.TransactionalEmailsApi(brevo_python.ApiClient(self.configuration))
        self.sender_email = sender_email
        self.sender_name = sender_name

    def send_verification_email(self, recipient_email: str, verification_url: str):
        """Send a verification email via Brevo API."""
        subject = "Verify Your Email Address"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #f8f9fa; padding: 30px; border-radius: 8px;">
                    <h2 style="color: #333; margin-top: 0;">Email Verification</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        Thank you for registering! Please verify your email address by clicking the button below:
                    </p>
                    <div style="text-align: center; margin: 40px 0;">
                        <a href="{verification_url}" 
                           style="background-color: #4CAF50; color: white; padding: 14px 32px; 
                                  text-decoration: none; border-radius: 6px; display: inline-block;
                                  font-weight: bold; font-size: 16px;">
                            Verify Email Address
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        Or copy and paste this link into your browser:
                    </p>
                    <p style="background-color: #fff; padding: 12px; border-radius: 4px; 
                              word-break: break-all; font-size: 13px; color: #333; border: 1px solid #ddd;">
                        {verification_url}
                    </p>
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                    <p style="color: #999; font-size: 12px; margin: 0;">
                        This link will expire in 48 hours. If you didn't request this verification, 
                        please ignore this email.
                    </p>
                </div>
            </body>
        </html>
        """

        send_smtp_email = brevo_python.SendSmtpEmail(
            to=[{"email": recipient_email}],
            sender={"name": self.sender_name, "email": self.sender_email},
            subject=subject,
            html_content=html_body
        )
        
        try:
            api_response = self.api_instance.send_transac_email(send_smtp_email)
            print(f"✅ Verification email sent to {recipient_email} via Brevo (Message ID: {api_response.message_id})")
            return True
        except ApiException as e:
            print(f"❌ Brevo API error: {getattr(e, 'body', str(e))}")
            return False
        except Exception as e:
            print(f"❌ Failed to send email via Brevo: {str(e)}")
            return False

    def send_templated_email(self, recipient_email: str, subject: str, html_content: str, sender_name: str = None):
        """Send a templated HTML email via Brevo API."""
        try:
            send_smtp_email = brevo_python.SendSmtpEmail(
                to=[{"email": recipient_email}],
                sender={"name": sender_name or self.sender_name, "email": self.sender_email},
                subject=subject,
                html_content=html_content
            )
            
            api_response = self.api_instance.send_transac_email(send_smtp_email)
            print(f"✅ Templated email sent to {recipient_email} via Brevo")
            return True
            
        except ApiException as e:
            print(f"❌ Brevo API error: {getattr(e, 'body', str(e))}")
            return False
        except Exception as e:
            print(f"❌ Failed to send templated email via Brevo: {str(e)}")
            return False

    def send_simple_email(self, recipient_email: str, subject: str, plain_text: str, sender_name: str = None):
        """Send a simple plain text email via Brevo API."""
        # Convert plain text to simple HTML
        html_content = f"<html><body><pre style='font-family: Arial, sans-serif;'>{plain_text}</pre></body></html>"
        
        try:
            send_smtp_email = brevo_python.SendSmtpEmail(
                to=[{"email": recipient_email}],
                sender={"name": sender_name or self.sender_name, "email": self.sender_email},
                subject=subject,
                html_content=html_content
            )
            
            api_response = self.api_instance.send_transac_email(send_smtp_email)
            print(f"✅ Simple email sent to {recipient_email} via Brevo")
            return True
            
        except ApiException as e:
            print(f"❌ Brevo API error: {getattr(e, 'body', str(e))}")
            return False
        except Exception as e:
            print(f"❌ Failed to send simple email via Brevo: {str(e)}")
            return False

