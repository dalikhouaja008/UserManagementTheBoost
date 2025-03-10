import { Module, forwardRef } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationResolver } from './authentication.resolver';
import { CoreModule } from '../core/core.module';
import { RolesModule } from '../roles/roles.module';
import { GuardsModule } from 'src/guards/guards.module';
import { AuthenticationMicroserviceResolver } from './authentication.microservice.resolver';
import { TokenService } from './token.service';
import { UserPreferencesService } from './user-preferences.service';
import { UserPreferencesResolver } from './user-preferences.resolver';
import { MongooseModule } from '@nestjs/mongoose';
import { UserPreferences, UserPreferencesSchema } from './schema/userPreferences.schema';
import { TwoFactorAuthService } from './TwoFactorAuth.service';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => RolesModule),
    forwardRef(() => GuardsModule),
    MongooseModule.forFeature([
      { name: UserPreferences.name, schema: UserPreferencesSchema }
    ])
  ],
  providers: [
    AuthenticationMicroserviceResolver,
    AuthenticationService,
    AuthenticationResolver,
    TokenService,
    TwoFactorAuthService,
    UserPreferencesService,
    UserPreferencesResolver
  ],
  exports: [
    AuthenticationService,
    UserPreferencesService
  ]
})
export class AuthenticationModule {}