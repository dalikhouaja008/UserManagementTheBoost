import { 
  Injectable, 
  CanActivate, 
  ExecutionContext,
  Logger,
  UnauthorizedException
} from '@nestjs/common';
import { Observable, firstValueFrom } from 'rxjs';
import { ClientProxy } from '@nestjs/microservices';
import { Inject } from '@nestjs/common';
import { SERVICES } from 'src/constants/service';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class MicroserviceAuthGuard implements CanActivate {
  private readonly logger = new Logger(MicroserviceAuthGuard.name);

  constructor(
    @Inject(SERVICES.LAND) private readonly landClient: ClientProxy
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const ctx = GqlExecutionContext.create(context);
      const { req } = ctx.getContext();

      // Extraction du token avec gestion des différents formats
      const token = this.extractToken(req);

      if (!token) {
        this.logger.warn('No authentication token provided');
        throw new UnauthorizedException('No authentication token provided');
      }

      // Authentification via le service Land
      const response = await firstValueFrom(
        this.landClient.send('authenticate', {
          Authentication: token,
          timestamp: new Date().toISOString(),
          source: 'user-management'
        })
      );

      if (!response || !response.success) {
        this.logger.warn('Authentication failed', { userId: response?.data?.userId });
        throw new UnauthorizedException(response?.error || 'Authentication failed');
      }

      // Ajout des informations utilisateur à la requête
      req.user = {
        ...response.data,
        token
      };

      this.logger.debug('Authentication successful', { 
        userId: response.data.userId,
        roles: response.data.roles 
      });

      return true;

    } catch (error) {
      this.logger.error('Authentication error', { 
        error: error.message,
        stack: error.stack 
      });
      
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      throw new UnauthorizedException('Authentication service unavailable');
    }
  }

  private extractToken(req: any): string | null {
    // Vérifier d'abord dans les cookies
    if (req.cookies?.Authentication) {
      return req.cookies.Authentication;
    }

    // Vérifier les headers (case insensitive)
    const authHeader = 
      req.headers?.authentication || 
      req.headers?.Authorization ||
      req.headers?.authorization;

    if (!authHeader) {
      return null;
    }

    // Gérer le format "Bearer token"
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    return authHeader;
  }
}