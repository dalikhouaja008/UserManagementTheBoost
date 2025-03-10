import { UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { UserPreferencesService } from '../authentication/user-preferences.service';
import { UserPreferences } from './schema/userPreferences.schema';
import { UserPreferencesInput } from './dto/userPreferences.input';

@Resolver(() => UserPreferences)
export class UserPreferencesResolver {
  constructor(private readonly userPreferencesService: UserPreferencesService) {}

  @Query(() => UserPreferences, { nullable: true })
  @UseGuards(AuthenticationGuard)
  async getUserPreferences(@Context() context) {
    const userId = context.req.user.userId;
    return this.userPreferencesService.findByUserId(userId);
  }

  @Mutation(() => UserPreferences)
  @UseGuards(AuthenticationGuard)
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