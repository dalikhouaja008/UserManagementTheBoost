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
import { MailService } from './services/mail.service';
import { TwilioService } from './services/twilio.service';
import { RedisCacheModule } from './redis/redis-cache.module';
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
        
        // Optional variables with default values
        TWILIO_ACCOUNT_SID: Joi.string().optional(),
        TWILIO_AUTH_TOKEN: Joi.string().optional(),
        TWILIO_PHONE_NUMBER: Joi.string().optional(),
        EMAIL_HOST: Joi.string().optional(),
        EMAIL_PORT: Joi.number().optional(),
        EMAIL_USER: Joi.string().optional(),
        EMAIL_PASS: Joi.string().optional(),
        EMAIL_FROM: Joi.string().optional(),
        FRONTEND_URL: Joi.string().optional(),
      }),
    }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: 'schema.graphql', // Sauvegarde le schéma dans un fichier
      context: ({ req }) => ({ req }), // Ajoutez cette ligne pour inclure la requête dans le contexte
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config) => ({
        uri: config.get('database.connectionString'),
      }),
      inject: [ConfigService],
    }),
    AuthenticationModule,
    RolesModule,
    ScheduleModule.forRoot(),
    CoreModule,
    GuardsModule,
    RedisCacheModule,
    HealthModule,
  ],
  
  providers: [
    MailService,
    TwilioService,
  ],
  exports: [
    MailService,
    TwilioService,
  ]
})
export class AppModule {}