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
import { RolesService } from 'src/roles/roles.service';


interface JWTPayload {
  userId: string;
  email?: string;
  role?: string;
  permissions?: any[];
  isTwoFactorAuthenticated?: boolean;
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private readonly logger = new Logger(AuthenticationGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly rolesService: RolesService
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

      // Vérifier si l'utilisateur nécessite une 2FA
      if (payload.isTwoFactorAuthenticated === false && request.path !== '/verify-2fa') {
        this.logger.warn(`2FA required for user ${payload.userId}`);
        throw new UnauthorizedException('Authentification à deux facteurs requise');
      }

      // Si les permissions ne sont pas dans le token, les récupérer du rôle
      if (payload.role && (!payload.permissions || payload.permissions.length === 0)) {
        try {
          const userRole = await this.rolesService.findByName(payload.role);
          payload.permissions = userRole.permissions;
        } catch (error) {
          this.logger.error(`Erreur lors de la récupération des permissions: ${error.message}`);
        }
      }

      this.logger.debug(`User authenticated with role: ${payload.role}`);
      this.logger.debug(`User permissions: ${JSON.stringify(payload.permissions)}`);

      // Ajouter le payload au request object
      request.user = {
        ...payload,
        permissions: payload.permissions || []
      };
      return true;
    } catch (error) {
      this.logger.error(`Erreur d'authentification: ${error.message}`, error.stack);
      throw new UnauthorizedException('Token invalide');
    }
  }
}