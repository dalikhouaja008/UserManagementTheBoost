import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationResolver } from './authentication.resolver';
import { CoreModule } from '../core/core.module';
import { RolesModule } from '../roles/roles.module';
import { GuardsModule } from 'src/guards/guards.module';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => RolesModule),
    forwardRef(() => GuardsModule)
  ],
  providers: [
    AuthenticationService,
    AuthenticationResolver
  ],
  exports: [
    AuthenticationService
  ]
})
export class AuthenticationModule {}