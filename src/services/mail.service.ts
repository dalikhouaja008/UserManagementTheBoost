import * as nodemailer from 'nodemailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);
  private readonly defaultSender: string;

  constructor(private configService: ConfigService) {
    const host = this.configService.get<string>('EMAIL_HOST');
    const port = this.configService.get<number>('EMAIL_PORT');
    const user = this.configService.get<string>('EMAIL_USER');
    const pass = this.configService.get<string>('EMAIL_PASS');
    this.defaultSender = this.configService.get<string>('EMAIL_FROM', 'Auth-backend service <noreply@example.com>');
    
    if (!host || !port || !user || !pass) {
      this.logger.warn('Email configuration incomplete. Email sending might not work properly.');
    }

    try {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465, // true for 465, false for other ports
        auth: {
          user,
          pass,
        },
        tls: {
          // Don't fail on invalid certs
          rejectUnauthorized: false
        }
      });
      
      this.logger.log('Email transporter initialized');
    } catch (error) {
      this.logger.error('Failed to initialize email transporter', error);
    }
  }

  async sendMail(mailOptions: { to: string; subject: string; text: string; html: string }): Promise<void> {
    if (!this.transporter) {
      this.logger.error('Email transporter not initialized. Cannot send email.');
      throw new Error('Email service not available');
    }
    
    try {
      this.logger.log(`Attempting to send email to ${mailOptions.to}`);
      await this.transporter.sendMail({
        from: this.defaultSender,
        ...mailOptions
      });
      this.logger.log(`Email sent to ${mailOptions.to}`);
    } catch (error) {
      this.logger.error('Error sending email:', error);
      throw new Error('Could not send email: ' + error.message);
    }
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:3000');
    const resetLink = `${frontendUrl}/reset-password?token=${token}`;
    
    const mailOptions = {
      to,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Your reset token is: ${token}. If you did not request this, please ignore this email.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e9e9e9; border-radius: 5px;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <div style="text-align: center; margin: 25px 0;">
            <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
          </div>
          <p>Or use this token: <strong>${token}</strong></p>
          <p>If you did not request this, please ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #e9e9e9; margin: 20px 0;">
          <p style="color: #777; font-size: 12px;">This is an automated message, please do not reply.</p>
        </div>
      `,
    };

    try {
      await this.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to ${to}`);
    } catch (error) {
      this.logger.error('Error sending password reset email:', error);
      throw new Error('Could not send password reset email: ' + error.message);
    }
  }
}