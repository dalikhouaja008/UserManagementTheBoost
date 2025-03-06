import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationGuard } from './authentication.guard';
import { CoreModule } from '../core/core.module';
import { AuthenticationModule } from '../authentication/authentication.module';
import { AuthorizationGuard } from './authorization.guards';
import { MicroserviceAuthGuard } from './microservice-auth.guard';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => AuthenticationModule) // Utilisation de forwardRef pour éviter la dépendance circulaire
  ],
  providers: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard
  ],
  exports: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard
  ]
})
export class GuardsModule {}