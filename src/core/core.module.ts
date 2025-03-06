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

@Global()
@Module({
  imports: [
    // Configuration JWT
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '10h' },
      }),
    }),
    // Configuration MongoDB
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: RoleSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema }
    ]),
    // Configuration Microservices
    ClientsModule.registerAsync([
      {
        name: 'LAND_SERVICE',
        useFactory: (config: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: config.get('LAND_SERVICE_HOST'),
            port: config.get('LAND_SERVICE_PORT'),
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
    MailService,
    TwoFactorAuthService,
    MicroserviceCommunicationService
  ]
})
export class CoreModule { }