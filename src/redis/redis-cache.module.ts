import { Module, Global } from '@nestjs/common';
import { RedisModule as NestRedisModule } from '@nestjs-modules/ioredis';
import { ConfigService } from '@nestjs/config';
import { RedisCacheService } from './redis-cahce.service';
import { RedisModule } from 'nestjs-redis/dist/redis.module';


@Global()
@Module({
  imports: [
    NestRedisModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: 'single',
        url: configService.get('REDIS_URL') || 'redis://localhost:6379',
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [RedisCacheService],
  exports: [RedisCacheService],
})
export class RedisCacheModule {}