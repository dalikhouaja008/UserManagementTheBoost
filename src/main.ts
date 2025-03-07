import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { Transport } from '@nestjs/microservices';
import * as cookieParser from 'cookie-parser';
import { MicroserviceErrorInterceptor } from './core/interceptors/microservice-error.interceptor';
import { MicroserviceExceptionFilter } from './core/filters/microservice-exveption.filter';

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
  app.use(cookieParser());

  app.enableCors();
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    whitelist: true,
    forbidNonWhitelisted: false,
  }));
  app.useGlobalFilters(new MicroserviceExceptionFilter());
  app.useGlobalInterceptors(new MicroserviceErrorInterceptor());

  await app.startAllMicroservices();
  await app.listen(process.env.HTTP_PORT || 3000);
}
bootstrap();
