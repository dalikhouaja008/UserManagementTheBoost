import { Injectable } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { RolesService } from './roles.service';
import { UserRole } from './enums/roles.enum';
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';


@Injectable()
export class MicroserviceRolesService {
  constructor(private readonly rolesService: RolesService) {}

  @MessagePattern('verify_role_permissions')
  async verifyRolePermissions(data: {
    roleName: UserRole;
    resource: Resource;
    requiredActions: Action[];
  }) {
    try {
      const permissions = await this.rolesService.getRolePermissions(data.roleName);
      
      const resourcePermission = permissions.find(
        p => p.resource === data.resource
      );

      if (!resourcePermission) {
        return { hasPermission: false };
      }

      const hasAllRequiredActions = data.requiredActions.every(
        action => resourcePermission.actions.includes(action)
      );

      return { 
        hasPermission: hasAllRequiredActions,
        permissions: resourcePermission
      };
    } catch (error) {
      return { 
        hasPermission: false,
        error: error.message
      };
    }
  }

  @MessagePattern('get_role_details')
  async getRoleDetails(data: { roleName: UserRole }) {
    try {
      const role = await this.rolesService.findByName(data.roleName);
      return {
        success: true,
        role: {
          name: role.name,
          permissions: role.permissions
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  @MessagePattern('validate_land_permissions')
  async validateLandPermissions(data: {
    roleName: UserRole;
    action: Action;
  }) {
    try {
      const role = await this.rolesService.findByName(data.roleName);
      
      // Vérification spécifique pour les permissions liées aux terrains
      const landPermissions = role.permissions.find(
        p => p.resource === Resource.LAND
      );

      // Vérification des rôles spéciaux
      const isSpecialRole = [
        UserRole.NOTAIRE,
        UserRole.GEOMETRE,
        UserRole.EXPERT_JURIDIQUE
      ].includes(role.name as UserRole);

      return {
        canAccess: isSpecialRole || (landPermissions?.actions.includes(data.action) ?? false),
        role: role.name,
        permissions: landPermissions
      };
    } catch (error) {
      return {
        canAccess: false,
        error: error.message
      };
    }
  }

  @MessagePattern('get_special_role_permissions')
  async getSpecialRolePermissions(data: {
    roleName: UserRole.NOTAIRE | UserRole.GEOMETRE | UserRole.EXPERT_JURIDIQUE;
  }) {
    try {
      const role = await this.rolesService.findByName(data.roleName);
      return {
        success: true,
        permissions: role.permissions,
        specificActions: this.getSpecificActionsForRole(data.roleName)
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  private getSpecificActionsForRole(role: UserRole): Action[] {
    switch (role) {
      case UserRole.NOTAIRE:
        return [Action.VALIDATE, Action.SIGN];
      case UserRole.GEOMETRE:
        return [Action.VALIDATE, Action.MEASURE];
      case UserRole.EXPERT_JURIDIQUE:
        return [Action.VALIDATE, Action.REVIEW];
      default:
        return [];
    }
  }
}