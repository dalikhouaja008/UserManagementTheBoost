import { Injectable, CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { MicroserviceCommunicationService } from 'src/core/services/micro-service.service';

@Injectable()
export class MicroserviceAuthGuard implements CanActivate {
  constructor(
    private readonly communicationService: MicroserviceCommunicationService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractToken(request);

    if (!token) {
      return false;
    }

    try {
      const validationResult = await this.communicationService.sendToLandService(
        'validate_token',
        { token }
      );

      if (validationResult.isValid) {
        request.user = validationResult.user;
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  private extractToken(request: any): string | undefined {
    return request.headers.authorization?.split(' ')[1];
  }
}