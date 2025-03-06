import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationGuard } from './authentication.guard';
import { CoreModule } from '../core/core.module';
import { AuthenticationModule } from '../authentication/authentication.module';
import { AuthorizationGuard } from './authorization.guards';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => AuthenticationModule) // Utilisation de forwardRef pour éviter la dépendance circulaire
  ],
  providers: [
    AuthenticationGuard,
    AuthorizationGuard
  ],
  exports: [
    AuthenticationGuard,
    AuthorizationGuard
  ]
})
export class GuardsModule {}