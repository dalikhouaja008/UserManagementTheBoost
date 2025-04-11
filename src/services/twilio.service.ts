import { Injectable, Logger } from '@nestjs/common';
import * as twilio from 'twilio';

@Injectable()
export class TwilioService {
  private readonly client: twilio.Twilio;
  private readonly logger = new Logger(TwilioService.name);

  constructor() {
    this.client = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
  }

  async sendSms(phoneNumber: string, message: string): Promise<void> {
    // Ensure phone number is in E.164 format
    const formattedNumber = phoneNumber.startsWith('+') ? phoneNumber : `+216${phoneNumber}`;
    
    try {
        const response = await this.client.messages.create({
            body: message,
            from: process.env.TWILIO_PHONE_NUMBER, // Ensure this is set in .env
            to: formattedNumber,
        });
        this.logger.log(`SMS sent successfully to ${formattedNumber}: SID ${response.sid}`);
    } catch (error) {
        this.logger.error(`Failed to send SMS: ${error.message}`);
        throw new Error('Failed to send SMS');
    }
}

}
