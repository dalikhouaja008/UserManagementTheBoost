import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { PERMISSIONS_KEY } from '../core/decorators/permissions.decorator';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get(
      PERMISSIONS_KEY,
      context.getHandler()
    );

    if (!requiredPermissions) {
      return true;
    }

    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();
    const user = req.user;

    if (!user || !user.permissions) {
      return false;
    }

    return this.matchPermissions(requiredPermissions, user.permissions);
  }

  private matchPermissions(required: any[], userPermissions: any[]): boolean {
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