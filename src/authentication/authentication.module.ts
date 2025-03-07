import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationResolver } from './authentication.resolver';
import { CoreModule } from '../core/core.module';
import { RolesModule } from '../roles/roles.module';
import { GuardsModule } from 'src/guards/guards.module';
import { MicroserviceCommunicationService } from 'src/core/services/micro-service.service';
import { AuthenticationMicroserviceResolver } from './authentication.microservice.resolver';

  @Module({
    imports: [
      CoreModule,
      forwardRef(() => RolesModule),
      forwardRef(() => GuardsModule)
    ],
    providers: [
      AuthenticationMicroserviceResolver,
      AuthenticationService,
      AuthenticationResolver
    ],
    exports: [
      AuthenticationService
    ]
  })
  export class AuthenticationModule {}