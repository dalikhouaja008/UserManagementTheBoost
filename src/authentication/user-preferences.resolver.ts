import { UnauthorizedException, UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { UserPreferencesService } from '../authentication/user-preferences.service';
import { UserPreferences } from './schema/userPreferences.schema';
import { UserPreferencesInput } from './dto/userPreferences.input';

@Resolver(() => UserPreferences)
export class UserPreferencesResolver {
  logger: any;
  constructor(private readonly userPreferencesService: UserPreferencesService) {}

  @Query(() => UserPreferences)

async getUserPreferences(@Context() context) {
  try {
    const userId = context.req.user.userId;
    return this.userPreferencesService.findByUserId(userId);
  } catch (error) {
    this.logger.error('Error fetching user preferences:', error);
    throw new UnauthorizedException('Unable to fetch user preferences');
  }
}

  @Mutation(() => UserPreferences)

  async updateUserPreferences(
    @Context() context,
    @Args('preferences') preferencesData: UserPreferencesInput,
  ) {
    const userId = context.req.user.userId;
    return this.userPreferencesService.upsertPreferences(userId, preferencesData);
  }

  @Query(() => [String])
  async getAvailableLandTypes() {
    // Return all available land types as strings
    return ['AGRICULTURAL', 'RESIDENTIAL', 'INDUSTRIAL', 'COMMERCIAL'];
  }
}