// src/guards/authentication.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { GqlExecutionContext } from '@nestjs/graphql';

interface JWTPayload {
  userId: string;
  email?: string;
  ethAddress?: string;
  role?: string;
  permissions?: any[];
  isTwoFactorAuthenticated?: boolean;
  sessionId?: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private readonly logger = new Logger(AuthenticationGuard.name);

  constructor(
    private readonly jwtService: JwtService,
  ) { }

  getRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }

  extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = this.getRequest(context);
    if (!request) {
      this.logger.error('Invalid request: Request object not found');
      throw new UnauthorizedException('Requête non valide');
    }

    const token = this.extractTokenFromHeader(request);
    if (!token) {
      this.logger.error('Authentication failed: Missing token');
      throw new UnauthorizedException('Token manquant');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JWTPayload>(token, {
        secret: process.env.JWT_SECRET || 'secret key',
      });

      // Check if 2FA is required
      if (payload.isTwoFactorAuthenticated === false && request.path !== '/verify-2fa') {
        this.logger.warn(`2FA required for user ${payload.userId}`);
        throw new UnauthorizedException('Authentification à deux facteurs requise');
      }

      // Add the payload to the request object
      request.user = payload;
      if (payload.sessionId) {
        request.sessionId = payload.sessionId;
      }
      
      return true;
    } catch (error) {
      this.logger.error(`Authentication error: ${error.message}`, error.stack);
      throw new UnauthorizedException('Invalid token');
    }
  }
}