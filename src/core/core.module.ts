import { Module, Global } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Role, RoleSchema } from '../roles/schemas/role.schema';
import { MailService } from '../services/mail.service';
import { TwoFactorAuthService } from '../authentication/TwoFactorAuth.service';
import { User, UserSchema } from 'src/authentication/schema/user.schema';
import { RefreshToken, RefreshTokenSchema } from 'src/authentication/schema/refreshToken.schema';
import { ResetToken, ResetTokenSchema } from 'src/authentication/schema/resetToken.schema';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { MicroserviceCommunicationService } from './services/micro-service.service';
import { SERVICES } from 'src/constants/service';
import { RedisModule } from '@nestjs-modules/ioredis';
import { RedisCacheModule } from 'src/redis/redis-cache.module';
import { RedisCacheService } from 'src/redis/redis-cahce.service';
import { BlockchainService } from 'src/blockchain/blockchain.service';
import { EmailTemplateService } from 'src/services/email-template.service';
import { VerificationToken, VerificationTokenSchema } from 'src/authentication/schema/verificationToken.schema';

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
      { name: ResetToken.name, schema: ResetTokenSchema },
      { name: VerificationToken.name, schema: VerificationTokenSchema } 
    ]),
    ClientsModule.registerAsync([
      {
        name: SERVICES.LAND,
        useFactory: (configService: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: configService.get('LAND_HOST', 'land'),
            port: configService.get('LAND_PORT', 5000),
            timeout: 5000,
            retryAttempts: 3,
            retryDelay: 1000,
          },
        }),
        inject: [ConfigService],
      },

    ]),
    /*RedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const host = configService.get<string>('REDIS_HOST');
        const port = configService.get<number>('REDIS_PORT');

        console.log('Redis Configuration:', { host, port });

        return {
          type: 'single',
          name: 'default',
          config: {
            host: host || '127.0.0.1',
            port: port || 6379,
            retryStrategy: (times: number) => {
              console.log(`Attempting to reconnect to Redis (attempt ${times})`);
              return Math.min(times * 1000, 5000);
            },
            enableReadyCheck: true,
            maxRetriesPerRequest: 3,
            onError: (err) => {
              console.error('Redis Error:', err);
            },
          },
        };
      },
    }),*/
    RedisCacheModule,
  ],
  providers: [
    EmailTemplateService,
    MailService,
    TwoFactorAuthService,
    MicroserviceCommunicationService,
    RedisCacheService,
    BlockchainService
  ],
  exports: [
    EmailTemplateService,
    JwtModule,
    MongooseModule,
    ClientsModule,
    MailService,
    TwoFactorAuthService,
    MicroserviceCommunicationService,
    RedisCacheService,
    BlockchainService,
    RedisCacheService,

  ]
})
export class CoreModule { }