// src/services/land-notification.resolver.ts
import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { LandNotificationService } from './land-notification.service';
import { AuthenticationGuard } from 'src/guards/authentication.guard';

@Resolver()
export class LandNotificationResolver {
  constructor(private readonly landNotificationService: LandNotificationService) {}

  @Mutation(() => Boolean)
  @UseGuards(AuthenticationGuard)
  async testLandNotification(
    @Context() context,
    @Args('landId', { nullable: true }) landId?: string,
  ): Promise<boolean> {
    try {
      const userId = context.req.user.userId;
      
      // If a specific land ID is provided, get it from the land service
      if (landId) {
        // Implementation would depend on your land service
        // This is a placeholder for the actual implementation
        const landData = { _id: landId, title: "Test Land", price: 100000, type: "RESIDENTIAL", location: "Test Location" };
        await this.landNotificationService.processNewLand(landData);
        return true;
      }
      
      // Otherwise, simulate a land notification for the current user
      const user = context.req.user;
      const testLand = {
        _id: 'test-land-id',
        title: 'Test Property Notification',
        type: 'RESIDENTIAL',
        location: 'Test Location',
        price: 150000,
        area: 1000,
        description: 'This is a test property to verify the notification system.'
      };
      
      await this.landNotificationService.processNewLand(testLand);
      return true;
    } catch (error) {
      console.error('Error in test land notification:', error);
      return false;
    }
  }
}