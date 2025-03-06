import { Module, forwardRef } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesResolver } from './roles.resolver';
import { CoreModule } from 'src/core/core.module';
import { GuardsModule } from 'src/guards/guards.module';
import { AuthenticationModule } from 'src/authentication/authentication.module';


@Module({
  imports: [
    CoreModule,
    GuardsModule,
    forwardRef(() => AuthenticationModule)
  ],
  providers: [
    RolesService,
    RolesResolver
  ],
  exports: [RolesService]
})
export class RolesModule {}
