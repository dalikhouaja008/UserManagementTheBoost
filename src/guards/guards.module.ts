// src/guards/guards.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthenticationGuard } from './authentication.guard';
import { AuthorizationGuard } from './authorization.guards';
import { MicroserviceAuthGuard } from './microservice-auth.guard';
import { CoreModule } from '../core/core.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    CoreModule,
    JwtModule, // Import JwtModule directly
  ],
  providers: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
  ],
  exports: [
    AuthenticationGuard,
    AuthorizationGuard,
    MicroserviceAuthGuard,
  ]
})
export class GuardsModule {}