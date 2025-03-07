import { Injectable, Inject, Logger } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import { PATTERNS, SERVICES } from 'src/constants/service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class MicroserviceCommunicationService {
  private readonly logger = new Logger(MicroserviceCommunicationService.name);

  constructor(
    @Inject(SERVICES.LAND) private readonly landClient: ClientProxy
  ) {}

  // Méthodes pour communiquer avec le service LAND
  async communicateWithLand(pattern: string, data: any) {
    return this.sendToService(
      this.landClient,
      pattern,
      data
    );
  }

  // Méthode générique pour les services
  private async sendToService<T, R>(
    client: ClientProxy,
    pattern: string,
    data: T,
    metadata: Record<string, any> = {}
  ): Promise<R> {
    const messageId = uuidv4();
    
    try {
      this.logger.debug(`Sending message ${messageId} to pattern ${pattern}`);
      
      const message = {
        data,
        metadata: {
          ...metadata,
          timestamp: new Date().toISOString(),
          messageId,
          service: 'user-management'
        }
      };

      const response = await firstValueFrom(
        client.send<R>(pattern, message)
      );

      this.logger.debug(`Received response for message ${messageId}`);
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to send message ${messageId} to pattern ${pattern}: ${error.message}`
      );
      throw error;
    }
  }
}