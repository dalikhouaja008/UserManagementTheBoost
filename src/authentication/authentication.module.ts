import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationResolver } from './authentication.resolver';
import { CoreModule } from '../core/core.module';
import { RolesModule } from '../roles/roles.module';
import { GuardsModule } from 'src/guards/guards.module';
import { AuthenticationMicroserviceResolver } from './authentication.microservice.resolver';
import { TokenService } from './token.service';

  @Module({
    imports: [
      CoreModule,
      forwardRef(() => RolesModule),
      forwardRef(() => GuardsModule)
    ],
    providers: [
      AuthenticationMicroserviceResolver,
      AuthenticationService,
      AuthenticationResolver,
      TokenService
    ],
    exports: [
      AuthenticationService
    ]
  })
  export class AuthenticationModule {}
