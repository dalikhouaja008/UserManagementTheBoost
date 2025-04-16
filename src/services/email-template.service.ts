// src/services/email-template.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import * as Handlebars from 'handlebars';

@Injectable()
export class EmailTemplateService {
  private readonly logger = new Logger(EmailTemplateService.name);
  private readonly templates: Map<string, HandlebarsTemplateDelegate> = new Map();
  private readonly baseUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.baseUrl = this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000';
    this.registerHelpers();
    this.loadTemplates();
  }

  /**
   * Load all email templates from templates/emails directory
   */
  private loadTemplates(): void {
    try {
      // If you're using templates from filesystem:
      /*
      const templatesDir = path.join(process.cwd(), 'templates', 'emails');
      const files = fs.readdirSync(templatesDir);
      
      for (const file of files) {
        if (file.endsWith('.hbs')) {
          const templateName = path.basename(file, '.hbs');
          const templateContent = fs.readFileSync(path.join(templatesDir, file), 'utf8');
          this.templates.set(templateName, Handlebars.compile(templateContent));
          this.logger.log(`Loaded email template: ${templateName}`);
        }
      }
      */
      
      // For now, let's compile inline templates:
      this.registerTemplate('verificationEmail', this.getVerificationTemplate());
      this.registerTemplate('passwordReset', this.getPasswordResetTemplate());
      this.registerTemplate('landMatches', this.getLandMatchesTemplate());
      this.registerTemplate('securityAlert', this.getSecurityAlertTemplate());
      this.registerTemplate('accountChange', this.getAccountChangeTemplate());
      this.registerTemplate('welcomeEmail', this.getWelcomeTemplate());
    } catch (error) {
      this.logger.error(`Failed to load email templates: ${error.message}`, error.stack);
    }
  }

  /**
   * Register Handlebars helpers
   */
  private registerHelpers(): void {
    Handlebars.registerHelper('formatDate', function(date: Date) {
      return date.toLocaleDateString();
    });
    
    Handlebars.registerHelper('formatPrice', function(price: number) {
      return price.toLocaleString() + ' TND';
    });
    
    Handlebars.registerHelper('formatArea', function(area: number) {
      return area.toLocaleString() + ' m²';
    });
    
    Handlebars.registerHelper('truncate', function(text: string, length: number) {
      if (text.length <= length) return text;
      return text.substring(0, length) + '...';
    });
  }

  /**
   * Register a template
   */
  private registerTemplate(name: string, templateContent: string): void {
    this.templates.set(name, Handlebars.compile(templateContent));
    this.logger.log(`Registered email template: ${name}`);
  }

  /**
   * Render a template with provided data
   */
  renderTemplate(templateName: string, data: any): string {
    const template = this.templates.get(templateName);
    
    if (!template) {
      this.logger.warn(`Template not found: ${templateName}`);
      return '';
    }
    
    try {
      // Add base URL to all templates
      const templateData = {
        ...data,
        baseUrl: this.baseUrl
      };
      
      return template(templateData);
    } catch (error) {
      this.logger.error(`Failed to render template ${templateName}: ${error.message}`);
      return '';
    }
  }

  // Template definitions
  private getVerificationTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Welcome to TheBoost!</h2>
        <p>Thank you for signing up. To verify your email address and activate your account, please click the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{baseUrl}}/verify-email?token={{token}}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">Verify Email Address</a>
        </div>
        <p>If the button doesn't work, you can also copy and paste the following link into your browser:</p>
        <p style="word-break: break-all; color: #666;">{{baseUrl}}/verify-email?token={{token}}</p>
        <p>This link will expire in 24 hours.</p>
        <p style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
          If you did not create an account, no further action is required.
        </p>
      </div>
    `;
  }

  private getPasswordResetTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Password Reset Request</h2>
        <p>You requested a password reset. Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{baseUrl}}/reset-password?token={{token}}" style="background-color: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Password</a>
        </div>
        <p>If the button doesn't work, you can also copy and paste the following link into your browser:</p>
        <p style="word-break: break-all; color: #666;">{{baseUrl}}/reset-password?token={{token}}</p>
        <p>This link will expire in 15 minutes.</p>
        <p style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
          If you did not request a password reset, please ignore this email or contact support if you have concerns.
        </p>
      </div>
    `;
  }

  private getLandMatchesTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">New Properties Match Your Preferences</h2>
        <p>We found {{lands.length}} new properties that match your preferences:</p>
        
        {{#each lands}}
        <div style="margin-bottom: 20px; padding: 15px; border: 1px solid #eee; border-radius: 5px;">
          <h3 style="margin-top: 0; color: #2c3e50;">{{title}}</h3>
          <p><strong>Type:</strong> {{type}}</p>
          <p><strong>Location:</strong> {{location}}</p>
          <p><strong>Price:</strong> {{formatPrice price}}</p>
          <p><strong>Area:</strong> {{formatArea area}}</p>
          {{#if description}}<p>{{truncate description 100}}</p>{{/if}}
          <a href="{{../baseUrl}}/lands/{{_id}}" 
             style="display: inline-block; background-color: #3498db; color: white; padding: 8px 15px; text-decoration: none; border-radius: 4px; font-weight: bold;">
             View Details
          </a>
        </div>
        {{/each}}
        
        <div style="text-align: center; margin-top: 30px;">
          <a href="{{baseUrl}}/preferences" 
             style="background-color: #9b59b6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">
             Update Your Preferences
          </a>
        </div>
        
        <p style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
          You're receiving this email because you've enabled notifications for matching properties.
          <br>
          <a href="{{baseUrl}}/preferences">Manage your notification settings</a>
        </p>
      </div>
    `;
  }

  private getSecurityAlertTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Security Alert</h2>
        <p>We detected a {{alertType}} on your account:</p>
        
        <div style="background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p><strong>Time:</strong> {{formatDate timestamp}}</p>
          <p><strong>Device:</strong> {{device}}</p>
          <p><strong>Location:</strong> {{location}}</p>
          <p><strong>IP Address:</strong> {{ipAddress}}</p>
        </div>
        
        <p>If this was you, no further action is needed.</p>
        
        <p>If you don't recognize this activity, please secure your account immediately:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{baseUrl}}/security/reset-password" 
             style="background-color: #e74c3c; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold; margin-right: 10px;">
             Reset Password
          </a>
          <a href="{{baseUrl}}/security/devices" 
             style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">
             Manage Devices
          </a>
        </div>
        
        <p style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
          For security reasons, you will always receive these alerts regardless of your notification preferences.
        </p>
      </div>
    `;
  }

  private getAccountChangeTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Account Update</h2>
        <p>Your account has been updated:</p>
        
        <div style="background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p><strong>Change Type:</strong> {{changeType}}</p>
          <p><strong>Time:</strong> {{formatDate timestamp}}</p>
          {{#if details}}
            <p><strong>Details:</strong> {{details}}</p>
          {{/if}}
        </div>
        
        <p>If you made this change, no further action is needed.</p>
        
        <p>If you didn't make this change, please contact our support team immediately:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{baseUrl}}/support" 
             style="background-color: #2ecc71; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">
             Contact Support
          </a>
        </div>
        
        <p style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
          This email was sent to keep you informed about important changes to your account.
        </p>
      </div>
    `;
  }

  private getWelcomeTemplate(): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Welcome to TheBoost!</h2>
        
        <p>Hello {{username}},</p>
        
        <p>Thank you for joining TheBoost! We're excited to have you as part of our community.</p>
        
        <p>With your account, you can:</p>
        
        <ul style="margin: 20px 0;">
          <li>Browse and find the perfect land property</li>
          <li>Save your favorite listings</li>
          <li>Receive notifications for properties matching your preferences</li>
          <li>Connect with notaries, surveyors, and legal experts</li>
        </ul>
        
        <p>To get started, you can complete these steps:</p>
        
        <div style="background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p>✅ Create an account (completed)</p>
          <p>⬜ Set up your preferences</p>
          <p>⬜ Browse available properties</p>
          <p>⬜ Complete your profile</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{baseUrl}}/preferences" 
             style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold; margin-right: 10px;">
             Set Preferences
          </a>
          <a href="{{baseUrl}}/browse" 
             style="background-color: #2ecc71; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">
             Browse Properties
          </a>
        </div>
        
        <p>If you have any questions, feel free to reach out to our support team.</p>
        
        <p>Best regards,<br>The TheBoost Team</p>
      </div>
    `;
  }
}