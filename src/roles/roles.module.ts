import { Module, forwardRef } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesResolver } from './roles.resolver';
import { CoreModule } from 'src/core/core.module';
import { GuardsModule } from 'src/guards/guards.module';
import { AuthenticationModule } from 'src/authentication/authentication.module';
import { MicroserviceRolesService } from './microservice-roles.service';


@Module({
  imports: [
    CoreModule,
    forwardRef(() => GuardsModule),
    forwardRef(() => AuthenticationModule)
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
