// src/roles/roles.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesResolver } from './roles.resolver';
import { CoreModule } from 'src/core/core.module';
import { GuardsModule } from 'src/guards/guards.module';
import { AuthenticationModule } from 'src/authentication/authentication.module';
import { MicroserviceRolesService } from './microservice-roles.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Role, RoleSchema } from './schemas/role.schema';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => GuardsModule),
    forwardRef(() => AuthenticationModule),
    // Add MongooseModule here to directly provide Role schema
    MongooseModule.forFeature([
      { name: Role.name, schema: RoleSchema }
    ])
  ],
  providers: [
    RolesService,
    RolesResolver,
    MicroserviceRolesService
  ],
  exports: [
    RolesService,
    MicroserviceRolesService
  ]
})
export class RolesModule {}