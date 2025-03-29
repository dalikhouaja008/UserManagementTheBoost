import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { CreateRoleDtoInput } from './dtos/role.dto';
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';
import { UserRole } from './enums/roles.enum';
import {  Role } from './schemas/role.schema';
import { Permission } from './schemas/permission.schema';

@Injectable()
export class RolesService {
  constructor(
    @InjectModel(Role.name) private roleModel: Model<Role>
  ) { }

  async onModuleInit() {
    await this.initializeDefaultRoles();
  }

  private async initializeDefaultRoles() {
    const defaultRoles = {
      // Administrateur
      [UserRole.ADMIN]: {
        permissions: Object.values(Resource).map(resource => ({
          resource,
          actions: Object.values(Action)
        }))
      },
      // Utilisateur Standard
      [UserRole.USER]: {
        permissions: [
          {
            resource: Resource.USERS,
            actions: [Action.READ]  // Voir son propre profil
          },
          {
            resource: Resource.LAND,
            actions: [
              Action.UPLOAD_LAND,    // Poster un terrain
              Action.EDIT_LAND,      // Modifier ses terrains
              Action.DELETE_LAND,    // Supprimer ses terrains
              Action.VIEW_OWN_LANDS  // Voir ses terrains
            ]
          }
        ]
      },

      // Notaire
      [UserRole.NOTAIRE]: {
        permissions: [
          {
            resource: Resource.LAND,
            actions: [
              Action.READ,
              Action.VALIDATE,
              Action.SIGN
            ]
          },
          {
            resource: Resource.AUTH,
            actions: [Action.READ]
          }
        ]
      },
      // Géomètre
      [UserRole.GEOMETRE]: {
        permissions: [
          {
            resource: Resource.LAND,
            actions: [
              Action.READ,
              Action.MEASURE,
              Action.VALIDATE
            ]
          },
          {
            resource: Resource.AUTH,
            actions: [Action.READ]
          }
        ]
      },
      // Expert Juridique
      [UserRole.EXPERT_JURIDIQUE]: {
        permissions: [
          {
            resource: Resource.LAND,
            actions: [
              Action.READ,
              Action.REVIEW,
              Action.VALIDATE
            ]
          },
          {
            resource: Resource.AUTH,
            actions: [Action.READ]
          }
        ]
      }
    };

    for (const [roleName, roleData] of Object.entries(defaultRoles)) {
      try {
        await this.roleModel.findOneAndUpdate(
          { name: roleName },
          { $setOnInsert: roleData },
          { upsert: true, new: true }
        );
        console.log(`✅ Role ${roleName} initialized`);
      } catch (error) {
        console.error(`❌ Error initializing role ${roleName}:`, error);
      }
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