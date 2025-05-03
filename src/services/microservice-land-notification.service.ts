// src/services/microservice-land-notification.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LandNotificationService } from './land-notification.service';

@Injectable()
export class MicroserviceLandNotificationService {
  private readonly logger = new Logger(MicroserviceLandNotificationService.name);

  constructor(private readonly landNotificationService: LandNotificationService) {}

  @MessagePattern('land.created')
  async handleLandCreated(@Payload() data: any) {
    try {
      this.logger.log(`Received land.created event for land ID: ${data.data?._id || 'unknown'}`);
      
      if (!data.data) {
        this.logger.warn('No land data received in payload');
        return { success: false, error: 'No land data received' };
      }
      
      // Process the land for notifications
      await this.landNotificationService.processNewLand(data.data);
      
      return {
        success: true,
        message: 'Land processed for notifications'
      };
    } catch (error) {
      this.logger.error(`Error processing land notification: ${error.message}`, error.stack);
      return {
        success: false,
        error: error.message
      };
    }
  }

  @MessagePattern('land.updated')
  async handleLandUpdated(@Payload() data: any) {
    try {
      this.logger.log(`Received land.updated event for land ID: ${data.data?._id || 'unknown'}`);
      
      if (!data.data) {
        this.logger.warn('No land data received in payload');
        return { success: false, error: 'No land data received' };
      }
      
      // Only process for notifications if there's a significant change
      // like price reduction or new features
      const significantChange = this.hasSignificantChange(data.data, data.oldData);
      
      if (significantChange) {
        await this.landNotificationService.processNewLand(data.data);
      }
      
      return {
        success: true,
        message: significantChange ? 'Land processed for notifications' : 'No significant changes detected'
      };
    } catch (error) {
      this.logger.error(`Error processing land update notification: ${error.message}`, error.stack);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Determine if a land update contains significant changes that warrant notifications
   */
  private hasSignificantChange(newData: any, oldData: any): boolean {
    if (!oldData) return true;
    
    // Price reduction of more than 5%
    if (newData.price && oldData.price && newData.price < oldData.price) {
      const reductionPercent = ((oldData.price - newData.price) / oldData.price) * 100;
      if (reductionPercent > 5) return true;
    }
    
    // Status change to available
    if (newData.status === 'AVAILABLE' && oldData.status !== 'AVAILABLE') {
      return true;
    }
    
    // Type change
    if (newData.type !== oldData.type) {
      return true;
    }
    
    // Any other criteria you want to consider as significant
    
    return false;
  }
}