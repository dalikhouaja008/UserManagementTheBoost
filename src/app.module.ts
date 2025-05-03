// src/app.module.ts
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { AuthenticationModule } from './authentication/authentication.module';
import { MongooseModule } from '@nestjs/mongoose';
import config from './config/config';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RolesModule } from './roles/roles.module';
import { ScheduleModule } from '@nestjs/schedule';
import { CoreModule } from './core/core.module';
import { GuardsModule } from './guards/guards.module';
import * as Joi from 'joi';
import { MailService, MailService } from './services/mail.service';
import { BlockchainModule } from './blockchain/blockchain.module';
import { RedisCacheModule } from './redis/redis-cache.module';
import { Role, RoleSchema } from './roles/schemas/role.schema';
import { RolesService } from './roles/roles.service';
import { HealthModule } from './health/health.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [config],
      validationSchema: Joi.object({
        JWT_SECRET: Joi.string().required(),
        JWT_EXPIRATION: Joi.string().required(),
        HTTP_PORT: Joi.number().required(),
        TCP_PORT: Joi.number().required(),
        REDIS_HOST: Joi.string().required(),
        REDIS_PORT: Joi.number().required(),
      }),
    }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: 'schema.graphql',
      context: ({ req }) => ({ req }),
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config) => ({
        uri: config.get('database.connectionString'),
      }),
      inject: [ConfigService],
    }),
    // Add direct reference to Role schema
    MongooseModule.forFeature([
      { name: Role.name, schema: RoleSchema }
    ]),
    RedisCacheModule,
    CoreModule,
    AuthenticationModule,
    RolesModule,
    GuardsModule, // Make sure GuardsModule is imported here
    ScheduleModule.forRoot(),
    HealthModule,
  ],
  providers: [
    MailService,
    // Add RolesService directly to app module
    BlockchainModule,
    RolesService
  ],
  exports: [
    RolesService
  ]
})
export class AppModule {}