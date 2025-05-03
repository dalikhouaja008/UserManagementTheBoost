// src/services/land-notification.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Cron, CronExpression } from '@nestjs/schedule';
import { MailService } from './mail.service';
import { User } from 'src/authentication/schema/user.schema';
import { UserPreferences } from 'src/authentication/schema/userPreferences.schema';
import { MicroserviceCommunicationService } from 'src/core/services/micro-service.service';

interface MicroserviceResponse {
    success: boolean;
    data?: any[];
    error?: string;
  }

@Injectable()
export class LandNotificationService {
  private readonly logger = new Logger(LandNotificationService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(UserPreferences.name) private readonly userPreferencesModel: Model<UserPreferences>,
    private readonly mailService: MailService,
    private readonly microserviceService: MicroserviceCommunicationService
  ) {}

  /**
   * Process new land matches against user preferences and send notifications
   * @param landData The new land data that was added
   */
  async processNewLand(landData: any): Promise<void> {
    try {
      this.logger.log(`Processing new land for notifications: ${landData._id}`);
      
      // Find users with matching preferences
      const matchingUsers = await this.findUsersWithMatchingPreferences(landData);
      
      if (matchingUsers.length === 0) {
        this.logger.debug('No users with matching preferences found');
        return;
      }
      
      // Send notifications to each matching user
      for (const user of matchingUsers) {
        await this.sendLandNotification(user, [landData]);
      }
      
      this.logger.log(`Notifications sent to ${matchingUsers.length} users for land ${landData._id}`);
    } catch (error) {
      this.logger.error(`Error processing land notification: ${error.message}`, error.stack);
    }
  }

  /**
   * Run a scheduled job to check for new lands and notify users
   */
  @Cron(CronExpression.EVERY_HOUR)
  async scheduledLandNotifications(): Promise<void> {
    try {
      this.logger.log('Running scheduled land notifications check');
      
      // Get all users with notifications enabled
      const users = await this.userModel.find({
        isVerified: true
      }).exec();
      
      for (const user of users) {
        await this.checkAndNotifyUser(user);
      }
      
      this.logger.log('Scheduled land notifications completed');
    } catch (error) {
      this.logger.error(`Error in scheduled land notifications: ${error.message}`, error.stack);
    }
  }

  /**
   * Check for matching lands for a specific user and send notification if found
   */
  private async checkAndNotifyUser(user: User): Promise<void> {
    try {
      // Get user preferences
      const preferences = await this.userPreferencesModel.findOne({ 
        userId: user._id 
      }).exec();
      
      if (!preferences || !preferences.notificationsEnabled) {
        return;
      }
      
      // Get last notification date from preferences or default to 24 hours ago
      const lastNotificationDate = new Date();
      lastNotificationDate.setHours(lastNotificationDate.getHours() - 24);
      
      // Get new matching lands from the land service
      const matchingLands = await this.getMatchingLands(preferences, lastNotificationDate);
      
      if (!matchingLands || matchingLands.length === 0) {
        return;
      }
      
      // Send notification email with matching lands
      await this.sendLandNotification(user, matchingLands);
      
      // Update last notification date
      preferences.lastUpdated = new Date();
      await preferences.save();
      
    } catch (error) {
      this.logger.error(`Error checking lands for user ${user._id}: ${error.message}`);
    }
  }

  /**
   * Find users whose preferences match the provided land
   */
  private async findUsersWithMatchingPreferences(land: any): Promise<User[]> {
    // Query for users with matching preferences
    const landType = land.type?.toUpperCase() || '';
    const location = land.location || '';
    const price = land.price || 0;
    
    const matchingPreferences = await this.userPreferencesModel.find({
      notificationsEnabled: true,
      preferredLandTypes: landType,
      minPrice: { $lte: price },
      maxPrice: { $gte: price },
      // Check if any of the preferred locations matches
      $or: [
        { preferredLocations: { $elemMatch: { $regex: location, $options: 'i' } } },
        { preferredLocations: { $size: 0 } } // Or if they haven't specified any locations
      ]
    }).exec();
    
    if (matchingPreferences.length === 0) {
      return [];
    }
    
    // Get the actual user objects
    const userIds = matchingPreferences.map(pref => pref.userId);
    return this.userModel.find({
      _id: { $in: userIds },
      isVerified: true,
    }).exec();
  }

  

  /**
   * Get matching lands from the land service based on user preferences
   */
  private async getMatchingLands(preferences: UserPreferences, since: Date): Promise<any[]> {
    try {
      // Prepare filter criteria based on preferences
      const criteria = {
        landTypes: preferences.preferredLandTypes,
        minPrice: preferences.minPrice,
        maxPrice: preferences.maxPrice,
        locations: preferences.preferredLocations,
        maxDistance: preferences.maxDistanceKm,
        createdSince: since.toISOString()
      };
      
      // Call the land service via microservice communication with type assertion
      const response = await this.microserviceService.communicateWithLand(
        'land.find_matching',
        criteria
      ) as MicroserviceResponse;
      
      if (!response || !response.success) {
        this.logger.warn(`Failed to get matching lands: ${response?.error || 'Unknown error'}`);
        return [];
      }
      
      return response.data || [];
    } catch (error) {
      this.logger.error(`Error getting matching lands: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  /**
   * Send notification email with matching lands to a user
   */
  private async sendLandNotification(user: User, lands: any[]): Promise<void> {
    if (!user.email || !lands.length) {
      return;
    }
    
    try {
      await this.mailService.sendMatchingLandsEmail(user.email, lands);
      this.logger.log(`Land notification email sent to ${user.email} with ${lands.length} properties`);
    } catch (error) {
      this.logger.error(`Failed to send land notification email to ${user.email}: ${error.message}`);
    }
  }
}