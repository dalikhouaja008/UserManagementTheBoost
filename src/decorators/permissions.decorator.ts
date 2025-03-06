import { SetMetadata } from '@nestjs/common';
import { Resource } from '../roles/enums/resource.enum';
import { Action } from '../roles/enums/action.enum';

export interface RequiredPermission {
  resource: Resource;
  actions: Action[];
}

export const PERMISSIONS_KEY = 'permissions';

export const Permissions = (...permissions: RequiredPermission[]) => 
  SetMetadata(PERMISSIONS_KEY, permissions);