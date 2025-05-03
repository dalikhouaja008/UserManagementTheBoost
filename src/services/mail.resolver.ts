// src/services/mail.resolver.ts
import { Resolver, Mutation, Args } from '@nestjs/graphql';
import { MailService } from './mail.service';

@Resolver()
export class MailResolver {
  constructor(private readonly mailService: MailService) {}

  @Mutation(() => Boolean, { description: 'Send a test email' })
  async sendTestEmail(
    @Args('email') email: string,
    @Args('subject', { defaultValue: 'Test Email from TheBoost' }) subject: string,
    @Args('message', { defaultValue: 'This is a test email from TheBoost application.' }) message: string,
  ): Promise<boolean> {
    return this.mailService.sendTestEmail(email, subject, message);
  }
}