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
import { TwilioService } from 'src/services/twilio.service';
import { SessionConfig } from 'src/config/session';

@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('jwt.secret'),
        signOptions: { 
          expiresIn: config.get<string>('jwt.expiration', '10h') 
        },
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
            retryAttempts: SessionConfig.RETRY_ATTEMPTS || 3,
            retryDelay: SessionConfig.RETRY_DELAY || 1000,
          },
        }),
        inject: [ConfigService],
      },
    ]),
    RedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const host = configService.get<string>('redis.host', 'localhost');
        const port = configService.get<number>('redis.port', 6379);

        console.log('Redis Configuration:', { host, port });

        return {
          type: 'single',
          name: 'default',
          config: {
            host,
            port,
            retryStrategy: (times: number) => {
              console.log(`Attempting to reconnect to Redis (attempt ${times})`);
              return Math.min(times * SessionConfig.RETRY_DELAY, 5000);
            },
            enableReadyCheck: true,
            maxRetriesPerRequest: SessionConfig.RETRY_ATTEMPTS,
            onError: (err) => {
              console.error('Redis Error:', err);
            },
          },
        };
      },
    }),
  ],
  providers: [
    MailService,
    TwilioService,
    TwoFactorAuthService,
    MicroserviceCommunicationService,
    RedisCacheService,
  ],
  exports: [
    JwtModule,
    MongooseModule,
    ClientsModule,
    MailService,
    TwilioService,
    TwoFactorAuthService,
    MicroserviceCommunicationService,
    RedisCacheService,
    RedisModule,
  ]
})
export class CoreModule {}