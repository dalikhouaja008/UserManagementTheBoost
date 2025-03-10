import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { UserPreferences } from './schema/userPreferences.schema';
import { UserPreferencesInput } from './dto/userPreferences.input';
import { User } from './schema/user.schema';
import { RedisCacheService } from 'src/redis/redis-cahce.service';

@Injectable()
export class UserPreferencesService {
  private readonly logger = new Logger(UserPreferencesService.name);

  constructor(
    @InjectModel(UserPreferences.name) private preferencesModel: Model<UserPreferences>,
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly redisCacheService: RedisCacheService
  ) {}

  async findByUserId(userId: string): Promise<UserPreferences | null> {
    try {
      // Check cache first
      const cachedPreferences = await this.redisCacheService.get(`user_preferences:${userId}`);
      if (cachedPreferences) {
        this.logger.debug(`Found preferences in cache for user ${userId}`);
        return cachedPreferences;
      }

      // Find in database
      const preferences = await this.preferencesModel.findOne({ userId: new Types.ObjectId(userId) });
      
      if (preferences) {
        // Cache for future requests
        await this.redisCacheService.set(
          `user_preferences:${userId}`,
          preferences,
          3600 // Cache for 1 hour
        );
      }
      
      return preferences;
    } catch (error) {
      this.logger.error(`Error finding preferences for user ${userId}: ${error.message}`);
      return null;
    }
  }

  async upsertPreferences(userId: string, preferencesData: UserPreferencesInput): Promise<UserPreferences> {
    this.logger.log(`Upserting preferences for user ${userId}`);
    
    try {
      // Ensure we have a valid ObjectId for the user
      const userObjectId = new Types.ObjectId(userId);
      
      // Create a new preferences object with an explicit ID
      const preferences = new this.preferencesModel({
        _id: new Types.ObjectId(), // Explicitly create an ID
        userId: userObjectId,
        preferredLandTypes: preferencesData.preferredLandTypes,
        minPrice: preferencesData.minPrice,
        maxPrice: preferencesData.maxPrice,
        preferredLocations: preferencesData.preferredLocations,
        maxDistanceKm: preferencesData.maxDistanceKm,
        notificationsEnabled: preferencesData.notificationsEnabled,
        lastUpdated: new Date()
      });
  
      // Try to find existing preferences first
      const existingPrefs = await this.preferencesModel.findOne({ userId: userObjectId });
  
      let savedPreferences;
      if (existingPrefs) {
        // Update existing preferences
        existingPrefs.preferredLandTypes = preferencesData.preferredLandTypes;
        existingPrefs.minPrice = preferencesData.minPrice;
        existingPrefs.maxPrice = preferencesData.maxPrice;
        existingPrefs.preferredLocations = preferencesData.preferredLocations;
        existingPrefs.maxDistanceKm = preferencesData.maxDistanceKm;
        existingPrefs.notificationsEnabled = preferencesData.notificationsEnabled;
        existingPrefs.lastUpdated = new Date();
        
        savedPreferences = await existingPrefs.save();
      } else {
        // Save new preferences
        savedPreferences = await preferences.save();
      }
  
      // Update the user document to reference these preferences
      await this.userModel.findByIdAndUpdate(
        userId,
        { preferences: savedPreferences._id },
        { new: true }
      );
  
      // Invalidate both user and preferences cache
      await this.redisCacheService.del(`user_preferences:${userId}`);
      const user = await this.userModel.findById(userId);
      if (user) {
        await this.redisCacheService.invalidateUser(userId, user.email);
      }
  
      // Cache the new preferences
      try {
        await this.redisCacheService.set(
          `user_preferences:${userId}`,
          savedPreferences,
          3600 // Cache for 1 hour
        );
      } catch (cacheError) {
        this.logger.warn(`Failed to cache preferences, but proceeding: ${cacheError.message}`);
      }
  
      return savedPreferences;
    } catch (error) {
      this.logger.error(`Error upserting preferences for user ${userId}: ${error.message}`, error.stack);
      throw error;
    }
  }
}