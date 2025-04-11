import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { SERVICES } from 'src/constants/service';
import { AuthenticationGuard } from './authentication.guard';
import { AuthorizationGuard } from './authorization.guards';
import { MicroserviceAuthGuard } from './microservice-auth.guard';
import { CoreModule } from '../core/core.module';
import { AuthenticationModule } from '../authentication/authentication.module';
import { RolesModule } from 'src/roles/roles.module';


@Module({
  imports: [
    CoreModule,
    forwardRef(() => AuthenticationModule),
    forwardRef(() => RolesModule),
  ],
  providers: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
    
    
  ],
  exports: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
    
    
  ]
})
export class GuardsModule {}