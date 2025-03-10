import { UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthenticationGuard, AllowWithout2FA } from 'src/guards/authentication.guard';
import { UserPreferencesService } from '../authentication/user-preferences.service';
import { UserPreferences } from './schema/userPreferences.schema';
import { UserPreferencesInput } from './dto/userPreferences.input';
import { Logger } from '@nestjs/common';

@Resolver(() => UserPreferences)
export class UserPreferencesResolver {
  private readonly logger = new Logger(UserPreferencesResolver.name);
  
  constructor(private readonly userPreferencesService: UserPreferencesService) {}

  @Query(() => UserPreferences, { nullable: true })
  @UseGuards(AuthenticationGuard)
  @AllowWithout2FA() // Allow querying preferences without 2FA
  async getUserPreferences(@Context() context) {
    try {
      const userId = context.req.user.userId;
      return this.userPreferencesService.findByUserId(userId);
    } catch (error) {
      this.logger.error(`Error getting preferences: ${error.message}`, error.stack);
      throw error;
    }
  }

  @Mutation(() => UserPreferences)
  @UseGuards(AuthenticationGuard)
  @AllowWithout2FA() // Allow updating preferences without 2FA
  async updateUserPreferences(
    @Context() context,
    @Args('preferences') preferencesData: UserPreferencesInput,
  ) {
    try {
      const userId = context.req.user.userId;
      const preferences = await this.userPreferencesService.upsertPreferences(userId, preferencesData);
      
      if (!preferences || !preferences._id) {
        throw new Error('Failed to create or update preferences');
      }
      
      return preferences;
    } catch (error) {
      this.logger.error(`Error updating preferences: ${error.message}`, error.stack);
      throw error;
    }
  }

  @Query(() => [String])
  async getAvailableLandTypes() {
    // Return all available land types as strings
    return ['AGRICULTURAL', 'RESIDENTIAL', 'INDUSTRIAL', 'COMMERCIAL'];
  }
}