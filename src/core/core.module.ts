import { Module, Global } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Role, RoleSchema } from '../roles/schemas/role.schema';
import { MailService } from '../services/mail.service';
import { TwoFactorAuthService } from '../authentication/TwoFactorAuth.service';
import { User, UserSchema } from 'src/authentication/schema/user.schema';
import { RefreshToken, RefreshTokenSchema } from 'src/authentication/schema/refreshToken.schema';
import { ResetToken, ResetTokenSchema } from 'src/authentication/schema/resetToken.schema';

@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '10h' },
      }),
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: RoleSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema }
    ])
  ],
  providers: [
    MailService,
    TwoFactorAuthService
  ],
  exports: [
    JwtModule,
    MongooseModule,
    MailService,
    TwoFactorAuthService
  ]
})
export class CoreModule {}