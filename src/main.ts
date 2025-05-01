import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { Transport } from '@nestjs/microservices';
import { MicroserviceErrorInterceptor } from './core/interceptors/microservice-error.interceptor';
import { MicroserviceExceptionFilter } from './core/filters/microservice-exveption.filter';
import { RedisCacheService } from './redis/redis-cahce.service';
const cookieParser = require('cookie-parser');

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Configuration Microservice
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
  // Ajoutez ces logs pour le débogage
  const redisCacheService = app.get(RedisCacheService);
  try {
    const isConnected = await redisCacheService.testConnection();
    console.log('Redis connection test:', isConnected ? 'Success' : 'Failed');
  } catch (error) {
    console.error('Redis connection test error:', error);
  }

  await app.startAllMicroservices();
  await app.listen(process.env.HTTP_PORT || 3000);
}
bootstrap();
