import { Injectable, Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class MicroserviceCommunicationService {
  constructor(
    @Inject('LAND_SERVICE') private readonly landServiceClient: ClientProxy
  ) {}

  async sendToLandService(pattern: string, data: any) {
    try {
      return await firstValueFrom(
        this.landServiceClient.send(pattern, data)
      );
    } catch (error) {
      throw new Error(`Land Service Communication Error: ${error.message}`);
    }
  }
}