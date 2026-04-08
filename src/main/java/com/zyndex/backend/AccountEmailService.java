package com.zyndex.backend;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
class AccountEmailService {
    private final JavaMailSender mailSender;
    private final AppProperties properties;

    AccountEmailService(JavaMailSender mailSender, AppProperties properties) {
        this.mailSender = mailSender;
        this.properties = properties;
    }

    void sendSignupConfirmationEmail(String name, String email) {
        if (properties.otpMailFrom() == null || properties.otpMailFrom().isBlank()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "SMTP email is not configured.");
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(properties.otpMailFrom());
            helper.setTo(email);
            helper.setSubject("Welcome to Zyndex");
            helper.setText(signupConfirmationText(name), signupConfirmationHtml(name));
            mailSender.send(message);
        } catch (MessagingException error) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, "Confirmation email could not be prepared.");
        }
    }

    private String signupConfirmationText(String name) {
        return """
                Dear %s,

                Welcome to Zyndex!

                We're delighted to inform you that your account has been created successfully. You can now log in using your registered email address and password to access our Educational Resource Library.

                If you have any questions or need assistance, please feel free to reach out to our support team through the Contact Us page - we're always here to help.

                We're excited to have you on board and wish you a rewarding and enriching learning experience with Zyndex!

                Best regards,
                Team Zyndex
                """.formatted(name);
    }

    private String signupConfirmationHtml(String name) {
        return """
                <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #172033;">
                  <p>Dear %s,</p>
                  <p>Welcome to <strong>Zyndex</strong>!</p>
                  <p>We're delighted to inform you that your account has been created successfully. You can now log in using your registered email address and password to access our <strong>Educational Resource Library</strong>.</p>
                  <p>If you have any questions or need assistance, please feel free to reach out to our support team through the <strong>Contact Us</strong> page - we're always here to help.</p>
                  <p>We're excited to have you on board and wish you a rewarding and enriching learning experience with Zyndex!</p>
                  <p>Best regards,<br/><strong>Team Zyndex</strong></p>
                </div>
                """.formatted(escapeHtml(name));
    }

    private String escapeHtml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
