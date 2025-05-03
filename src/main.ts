// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { Transport } from '@nestjs/microservices';
import { MicroserviceErrorInterceptor } from './core/interceptors/microservice-error.interceptor';
import { MicroserviceExceptionFilter } from './core/filters/microservice-exveption.filter';
import { RedisCacheService } from './redis/redis-cahce.service';
const cookieParser = require('cookie-parser');
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  try {
    logger.log('Starting application...');
    
    const app = await NestFactory.create(AppModule, {
      // Add logger
      logger: ['error', 'warn', 'log', 'debug', 'verbose'],
    });

    // Configuration Microservice
    logger.log('Configuring microservices...');
    app.connectMicroservice({
      transport: Transport.TCP,
      options: {
        host: '0.0.0.0',
        port: process.env.TCP_PORT || 3002,
      },
    });
    
    // Configuration Redis Microservice
    app.connectMicroservice({
      transport: Transport.REDIS,
      options: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        retryAttempts: 5,
        retryDelay: 1000,
      },
    });
    
    app.use(cookieParser());

    app.enableCors();
    app.useGlobalPipes(new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: false,
    }));
    app.useGlobalFilters(new MicroserviceExceptionFilter());
    app.useGlobalInterceptors(new MicroserviceErrorInterceptor());
    
    // Test Redis connection
    logger.log('Testing Redis connection...');
    try {
      const redisCacheService = app.get(RedisCacheService);
      const isConnected = await redisCacheService.testConnection();
      logger.log(`Redis connection test: ${isConnected ? 'Success' : 'Failed'}`);
    } catch (error) {
      logger.error(`Redis connection test error: ${error.message}`, error.stack);
    }

    logger.log('Starting microservices...');
    await app.startAllMicroservices();
    
    const port = process.env.HTTP_PORT || 3000;
    await app.listen(port);
    logger.log(`Application is running on port ${port}`);
    
  } catch (error) {
    logger.error(`Error during application bootstrap: ${error.message}`, error.stack);
  }
}

bootstrap();