import * as nodemailer from 'nodemailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('EMAIL_HOST'),
      port: this.configService.get<number>('EMAIL_PORT'),
      auth: {
        user: this.configService.get<string>('EMAIL_USER'),
        pass: this.configService.get<string>('EMAIL_PASS'),
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
    const resetLink = `${this.configService.get<string>('FRONTEND_URL')}/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth-backend service <elhadjyosri@gmail.com>',
      to,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="${resetLink}">Reset Password</a></p>
        <p>If you did not request this, please ignore this email.</p>
      `,
    };

    try {
      this.logger.log(`Attempting to send password reset email to ${to} with token ${token}`);
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to ${to}`);
    } catch (error) {
      this.logger.error('Error sending password reset email:', error.message);
      throw new Error('Could not send password reset email');
    }
  }
}