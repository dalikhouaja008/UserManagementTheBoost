import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { CreateRoleDtoInput } from './dtos/role.dto';
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';
import { UserRole } from './enums/roles.enum';
import { Permission, Role } from './schemas/role.schema';

@Injectable()
export class RolesService {
  constructor(
    @InjectModel(Role.name) private roleModel: Model<Role>
  ) {}

  async onModuleInit() {
    await this.initializeDefaultRoles();
  }

  private async initializeDefaultRoles() {
    const defaultRoles = {
      [UserRole.ADMIN]: {
        permissions: Object.values(Resource).map(resource => ({
          resource,
          actions: Object.values(Action)
        }))
      },
      [UserRole.USER]: {
        permissions: [
          {
            resource: Resource.USERS,
            actions: [Action.read]  // L'utilisateur peut voir son propre profil
          }
        ]
      },
      [UserRole.NOTAIRE]: {
        permissions: [
          {
            resource: Resource.AUTH,
            actions: [Action.read]  // Uniquement pour l'authentification
          }
        ]
      },
      [UserRole.GEOMETRE]: {
        permissions: [
          {
            resource: Resource.AUTH,
            actions: [Action.read]  // Uniquement pour l'authentification
          }
        ]
      },
      [UserRole.EXPERT_JURIDIQUE]: {
        permissions: [
          {
            resource: Resource.AUTH,
            actions: [Action.read]  // Uniquement pour l'authentification
          }
        ]
      }
    };
  
    for (const [roleName, roleData] of Object.entries(defaultRoles)) {
      await this.roleModel.findOneAndUpdate(
        { name: roleName },
        { $setOnInsert: roleData },
        { upsert: true, new: true }
      );
    }
  }

  async findAll(): Promise<Role[]> {
    return this.roleModel.find().exec();
  }

  async findByName(name: string): Promise<Role> {
    const role = await this.roleModel.findOne({ name }).exec();
    if (!role) {
      throw new NotFoundException(`Role ${name} not found`);
    }
    return role;
  }

  async createRole(name: string, permissions: Permission[]): Promise<Role> {
    const existingRole = await this.roleModel.findOne({ name }).exec();
    if (existingRole) {
      throw new BadRequestException(`Role ${name} already exists`);
    }

    return this.roleModel.create({ name, permissions });
  }

  async updateRole(name: string, permissions: Permission[]): Promise<Role> {
    const updatedRole = await this.roleModel.findOneAndUpdate(
      { name },
      { $set: { permissions } },
      { new: true }
    ).exec();

    if (!updatedRole) {
      throw new NotFoundException(`Role ${name} not found`);
    }

    return updatedRole;
  }

  async deleteRole(name: string): Promise<void> {
    const result = await this.roleModel.deleteOne({ name }).exec();
    if (result.deletedCount === 0) {
      throw new NotFoundException(`Role ${name} not found`);
    }
  }

  async getRolePermissions(roleName: string) {
    const role = await this.roleModel.findOne({ name: roleName });
    if (!role) {
      throw new NotFoundException(`Role ${roleName} not found`);
    }

    // Retourner les permissions spécifiques au rôle
    return role.permissions.map(permission => ({
      resource: permission.resource,
      actions: permission.actions
    }));
  }
}