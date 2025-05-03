// src/authentication/user-profile.resolver.ts
import { Resolver, Args, Mutation, Context, Query } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationGuard } from '../guards/authentication.guard';
import { User } from './schema/user.schema';
import { UserProfileInput } from './dto/user-profile.input';

@Resolver(() => User)
export class UserProfileResolver {
  constructor(private readonly authService: AuthenticationService) {}

  @Query(() => User)
  @UseGuards(AuthenticationGuard)
  async getMyProfile(@Context() context) {
    const userId = context.req.user.userId;
    return this.authService.findUser(userId, 'id', true);
  }

  @Mutation(() => User)
  @UseGuards(AuthenticationGuard)
  async updateProfile(
    @Context() context,
    @Args('profileData') profileData: UserProfileInput
  ): Promise<User> {
    const userId = context.req.user.userId;
    return this.authService.updateUserProfile(userId, profileData);
  }
}