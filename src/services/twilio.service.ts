import { Injectable, Logger } from '@nestjs/common';
import * as twilio from 'twilio';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class TwilioService {
  private readonly client: twilio.Twilio;
  private readonly logger = new Logger(TwilioService.name);

  constructor(private configService: ConfigService) {
    const accountSid = this.configService.get<string>('TWILIO_ACCOUNT_SID');
    const authToken = this.configService.get<string>('TWILIO_AUTH_TOKEN');
    
    if (!accountSid || !authToken) {
      this.logger.warn('Twilio credentials not properly configured! SMS sending will be disabled.');
    }
    
    try {
      this.client = twilio(accountSid, authToken);
      this.logger.log('Twilio client initialized');
    } catch (error) {
      this.logger.error('Failed to initialize Twilio client', error);
    }
  }

  async sendSms(phoneNumber: string, message: string): Promise<void> {
    // Validate Twilio client
    if (!this.client) {
      this.logger.error('Twilio client not initialized. Cannot send SMS.');
      throw new Error('SMS service not available');
    }
    
    // Ensure phone number is in E.164 format
    const formattedNumber = phoneNumber.startsWith('+') ? phoneNumber : `+216${phoneNumber}`;
    const fromNumber = this.configService.get<string>('TWILIO_PHONE_NUMBER');
    
    if (!fromNumber) {
      this.logger.error('TWILIO_PHONE_NUMBER not configured');
      throw new Error('SMS service configuration incomplete');
    }
    
    try {
      const response = await this.client.messages.create({
        body: message,
        from: fromNumber,
        to: formattedNumber,
      });
      this.logger.log(`SMS sent successfully to ${formattedNumber}: SID ${response.sid}`);
    } catch (error) {
      this.logger.error(`Failed to send SMS: ${error.message}`, error.stack);
      throw new Error('Failed to send SMS');
    }
  }
}