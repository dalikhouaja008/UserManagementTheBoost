// src/guards/authorization.guards.ts
import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { PERMISSIONS_KEY, RequiredPermission } from '../core/decorators/permissions.decorator';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  private readonly logger = new Logger(AuthorizationGuard.name);

  constructor(
    private reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<RequiredPermission[]>(
      PERMISSIONS_KEY,
      context.getHandler()
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true; // No permissions required
    }

    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();
    const user = req.user;

    if (!user) {
      this.logger.warn('User not found in request');
      return false;
    }

    if (!user.permissions || user.permissions.length === 0) {
      this.logger.warn(`No permissions found for user ${user.userId}`);
      return false;
    }

    const hasPermission = this.matchPermissions(requiredPermissions, user.permissions);
    if (!hasPermission) {
      this.logger.warn(`User ${user.userId} lacks required permissions`);
    }

    return hasPermission;
  }

  private matchPermissions(required: RequiredPermission[], userPermissions: any[]): boolean {
    return required.every(permission =>
      userPermissions.some(userPerm =>
        userPerm.resource === permission.resource &&
        permission.actions.every(action =>
          userPerm.actions.includes(action)
        )
      )
    );
  }
}