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



@Module({
  imports: [
    ConfigModule.forRoot({ //facilite l'utilisation des variables d'environnement
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
    
  ],
})
export class AppModule {}