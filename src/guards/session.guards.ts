import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { TokenService } from 'src/authentication/token.service';
import { SessionConfig } from 'src/config/session';


@Injectable()
export class SessionGuard implements CanActivate {
    constructor(private readonly tokenService: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Obtenir le contexte GraphQL
    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();

    // Vérifier si c'est une mutation de login
    if (this.isLoginMutation(ctx)) {
      return this.handleLoginAttempt(req.user?.userId);
    }

    // Pour les autres requêtes, vérifier si la session est valide
    return this.validateExistingSession(req.user?.userId, req.sessionId);
  }

  private isLoginMutation(context: GqlExecutionContext): boolean {
    const info = context.getInfo();
    return info.operation.operation === 'mutation' && 
           info.fieldName === 'login';
  }

  private async handleLoginAttempt(userId: string): Promise<boolean> {
    if (!userId) return true; // Permettre la tentative de connexion

    const activeSessions = await this.tokenService.getAllSessions(userId);

    if (activeSessions.length >= SessionConfig.MAX_SESSIONS_PER_USER) {
      throw new UnauthorizedException(
        `Maximum number of sessions (${SessionConfig.MAX_SESSIONS_PER_USER}) reached. Please logout from another device.`
      );
    }

    return true;
  }

  private async validateExistingSession(userId: string, sessionId: string): Promise<boolean> {
    if (!userId || !sessionId) {
      throw new UnauthorizedException('Invalid session');
    }

    // Vérifier si la session existe et est active
    const session = await this.tokenService.getSession(userId, sessionId);
    if (!session) {
      throw new UnauthorizedException('Session expired or invalid');
    }

    // Vérifier l'inactivité
    const lastActive = new Date(session.lastActive).getTime();
    const now = Date.now();
    if (now - lastActive > SessionConfig.INACTIVE_TIMEOUT * 1000) {
      await this.tokenService.revokeSession(userId, sessionId);
      throw new UnauthorizedException('Session expired due to inactivity');
    }

    // Mettre à jour le timestamp de dernière activité
    await this.tokenService.updateLastActive(userId, sessionId);

    return true;
  }
}