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
import { ClientsModule, Transport } from '@nestjs/microservices';
import { MicroserviceCommunicationService } from './services/micro-service.service';
import { SERVICES } from 'src/constants/service';

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
    ]),
    ClientsModule.registerAsync([
      {
        name: SERVICES.LAND,
        useFactory: (configService: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: configService.get('LAND_HOST', 'land'),
            port: configService.get('LAND_PORT', 3003),
            timeout: 5000,
            retryAttempts: 3,
            retryDelay: 1000,
          },
        }),
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [
    MailService,
    TwoFactorAuthService,
    MicroserviceCommunicationService
  ],
  exports: [
    JwtModule,
    MongooseModule,
    ClientsModule,
    MailService,
    TwoFactorAuthService,
    MicroserviceCommunicationService
  ]
})
export class CoreModule { }