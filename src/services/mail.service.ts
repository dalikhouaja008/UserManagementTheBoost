// src/services/mail.service.ts
import * as nodemailer from 'nodemailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EmailTemplateService } from './email-template.service';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(
    private configService: ConfigService,
    private emailTemplateService: EmailTemplateService
  ) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('MAIL_HOST') || 'smtp.gmail.com',
      port: this.configService.get<number>('MAIL_PORT') || 587,
      auth: {
        user: this.configService.get<string>('MAIL_USER'),
        pass: this.configService.get<string>('MAIL_PASSWORD'),
      },
      secure: false, // true for 465, false for other ports
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

  async sendMail(mailOptions: { to: string; subject: string; text: string; html: string }): Promise<void> {
    try {
      this.logger.log(`Attempting to send email to ${mailOptions.to}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent to ${mailOptions.to}`);
    } catch (error) {
      this.logger.error('Error sending email:', error.message);
      throw new Error('Could not send email');
    }
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const html = this.emailTemplateService.renderTemplate('passwordReset', { token });
    
    const mailOptions = {
      from: 'TheBoost <elhadjyosri@gmail.com>',
      to,
      subject: 'Password Reset Request',
      html,
    };

    try {
      this.logger.log(`Attempting to send password reset email to ${to}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to ${to}`);
    } catch (error) {
      this.logger.error('Error sending password reset email:', error.message);
      throw new Error('Could not send password reset email');
    }
  }

  // Send test email
  async sendTestEmail(to: string, subject: string, message: string): Promise<boolean> {
    const mailOptions = {
      from: 'TheBoost <elhadjyosri@gmail.com>',
      to,
      subject,
      text: message,
      html: `<p>${message}</p>`,
    };

    try {
      this.logger.log(`Sending test email to ${to}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Test email successfully sent to ${to}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to send test email: ${error.message}`);
      throw new Error(`Could not send test email: ${error.message}`);
    }
  }

  // Send email verification link after user signup
  async sendVerificationEmail(to: string, token: string): Promise<void> {
    const html = this.emailTemplateService.renderTemplate('verificationEmail', { token });
    
    const mailOptions = {
      from: 'TheBoost <elhadjyosri@gmail.com>',
      to,
      subject: 'Verify Your Email Address',
      html,
    };

    try {
      this.logger.log(`Sending verification email to ${to}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Verification email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send verification email: ${error.message}`);
      throw new Error(`Could not send verification email: ${error.message}`);
    }
  }

  // Send welcome email after verification
  async sendWelcomeEmail(to: string, username: string): Promise<void> {
    const html = this.emailTemplateService.renderTemplate('welcomeEmail', { username });
    
    const mailOptions = {
      from: 'TheBoost <elhadjyosri@gmail.com>',
      to,
      subject: 'Welcome to TheBoost!',
      html,
    };

    try {
      this.logger.log(`Sending welcome email to ${to}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Welcome email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send welcome email: ${error.message}`);
      // Don't throw here - welcome email is not critical
    }
  }

  // Send notifications for matching land properties
  async sendMatchingLandsEmail(to: string, lands: any[]): Promise<void> {
    if (!lands || lands.length === 0) {
      this.logger.warn(`No lands to send in notification to ${to}`);
      return;
    }

    const html = this.emailTemplateService.renderTemplate('landMatches', { lands });
    
    const mailOptions = {
      from: 'TheBoost Notifications <elhadjyosri@gmail.com>',
      to,
      subject: `${lands.length} New Properties Match Your Preferences`,
      html,
    };

    try {
      this.logger.log(`Sending matching lands email to ${to} with ${lands.length} properties`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Matching lands email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send matching lands email: ${error.message}`);
      throw new Error(`Could not send matching lands notification: ${error.message}`);
    }
  }

  // Send security alert (new login, password change, etc.)
  async sendSecurityAlert(to: string, alertData: any): Promise<void> {
    const html = this.emailTemplateService.renderTemplate('securityAlert', alertData);
    
    const mailOptions = {
      from: 'TheBoost Security <elhadjyosri@gmail.com>',
      to,
      subject: `Security Alert: ${alertData.alertType}`,
      html,
    };

    try {
      this.logger.log(`Sending security alert to ${to}: ${alertData.alertType}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Security alert sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send security alert: ${error.message}`);
      // Log but don't throw - security alerts should not block user actions
    }
  }

  // Send account change notification
  async sendAccountChangeEmail(to: string, changeData: any): Promise<void> {
    const html = this.emailTemplateService.renderTemplate('accountChange', changeData);
    
    const mailOptions = {
      from: 'TheBoost <elhadjyosri@gmail.com>',
      to,
      subject: `Account Update: ${changeData.changeType}`,
      html,
    };

    try {
      this.logger.log(`Sending account change email to ${to}: ${changeData.changeType}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Account change email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send account change email: ${error.message}`);
      // Log but don't throw - account change notifications should not block user actions
    }
  }
}