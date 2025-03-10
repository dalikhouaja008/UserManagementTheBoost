import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { SERVICES } from 'src/constants/service';
import { AuthenticationGuard } from './authentication.guard';
import { AuthorizationGuard } from './authorization.guards';
import { MicroserviceAuthGuard } from './microservice-auth.guard';
import { CoreModule } from '../core/core.module';
import { AuthenticationModule } from '../authentication/authentication.module';
import { SessionGuard } from './session.guards';
import { TokenService } from 'src/authentication/token.service';
import { RedisCacheService } from 'src/redis/redis-cahce.service';

@Module({
  imports: [
    CoreModule,
    forwardRef(() => AuthenticationModule),
    ClientsModule.registerAsync([
      {
        name: SERVICES.LAND,
        imports: [ConfigModule],
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
      }
    ]),
  ],
  providers: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
    SessionGuard,
  ],
  exports: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
    SessionGuard,
  ]
})
export class GuardsModule {}