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
import { TwilioService } from 'src/services/twilio.service';
import { MailService } from 'src/services/mail.service';
import { User, UserSchema } from './schema/user.schema';
import { RefreshToken, RefreshTokenSchema } from './schema/refreshToken.schema';
import { ResetToken, ResetTokenSchema } from './schema/resetToken.schema';
import { SessionGuard } from 'src/guards/session.guards';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => RolesModule),
    forwardRef(() => GuardsModule),
    MongooseModule.forFeature([
      { name: UserPreferences.name, schema: UserPreferencesSchema },
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema }
    ])
  ],
  providers: [
    AuthenticationMicroserviceResolver,
    AuthenticationService,
    AuthenticationResolver,
    TokenService,
    TwoFactorAuthService,
    UserPreferencesService,
    UserPreferencesResolver,
    SessionGuard
  ],
  exports: [
    AuthenticationService,
    UserPreferencesService,
    TokenService,
    TwoFactorAuthService
  ]
})
export class AuthenticationModule {}