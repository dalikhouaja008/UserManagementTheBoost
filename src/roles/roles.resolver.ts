import { Resolver, Query, Mutation, Args, ID } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { RolesService } from './roles.service';
import { Permission, Role } from './schemas/role.schema';
import { AuthenticationGuard } from '../guards/authentication.guard';
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';
import { AuthorizationGuard } from 'src/guards/authorization.guards';
import { CreateRoleInput } from './dtos/create-role.input';
import { UpdateRoleInput } from './dtos/update-role.input';
import { Permissions } from '../decorators/permissions.decorator';

@Resolver(() => Role)
export class RolesResolver {
  constructor(private readonly rolesService: RolesService) {}

  @Query(() => [Role])
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.READ]
  })
  async roles() {
    return this.rolesService.findAll();
  }

  @Query(() => Role)
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.READ]
  })
  async role(@Args('name') name: string) {
    return this.rolesService.findByName(name);
  }

  @Mutation(() => Role)
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.CREATE]
  })
  async createRole(
    @Args('createRoleInput') createRoleInput: CreateRoleInput
  ) {
    return this.rolesService.createRole(
      createRoleInput.name,
      createRoleInput.permissions
    );
  }

  @Mutation(() => Role)
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.UPDATE]
  })
  async updateRole(
    @Args('updateRoleInput') updateRoleInput: UpdateRoleInput
  ) {
    return this.rolesService.updateRole(
      updateRoleInput.name,
      updateRoleInput.permissions
    );
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.DELETE]
  })
  async deleteRole(@Args('name') name: string) {
    await this.rolesService.deleteRole(name);
    return true;
  }

  @Query(() => [Permission])
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.ROLES,
    actions: [Action.READ]
  })
  async getRolePermissions(@Args('name') name: string) {
    return this.rolesService.getRolePermissions(name);
  }
}
