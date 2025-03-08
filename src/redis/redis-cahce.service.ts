import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { User } from 'src/authentication/schema/user.schema';
import { InjectRedis } from '@nestjs-modules/ioredis';

@Injectable()
export class RedisCacheService {
  private readonly logger = new Logger(RedisCacheService.name);
  private readonly ttl = 3600; // 1 heure en secondes

  constructor(
    @InjectRedis() private readonly redis: Redis
  ) {
    this.redis.on('connect', () => {
      this.logger.log('Redis client connected');
    });

    this.redis.on('error', (error) => {
      this.logger.error('Redis client error:', error);
    });
  }

  async get(key: string): Promise<any> {
    try {
      const data = await this.redis.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      this.logger.error(`Error getting key ${key}:`, error);
      return null;
    }
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    try {
      if (ttl) {
        await this.redis.set(key, JSON.stringify(value), 'EX', ttl);
      } else {
        await this.redis.set(key, JSON.stringify(value));
      }
    } catch (error) {
      this.logger.error(`Error setting key ${key}:`, error);
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.redis.del(key);
    } catch (error) {
      this.logger.error(`Error deleting key ${key}:`, error);
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      const result = await this.redis.ping();
      this.logger.log(`Redis ping result: ${result}`);
      return result === 'PONG';
    } catch (error) {
      this.logger.error('Redis ping failed:', error);
      return false;
    }
  }

  async getUserById(userId: string): Promise<User | null> {
    try {
      const cachedUser = await this.redis.get(`user:id:${userId}`);
      return cachedUser ? JSON.parse(cachedUser) : null;
    } catch (error) {
      this.logger.error(`Error getting user from cache: ${error.message}`);
      return null;
    }
  }

  async getUserByEmail(email: string): Promise<User | null> {
    try {
      const cachedUser = await this.redis.get(`user:email:${email}`);
      return cachedUser ? JSON.parse(cachedUser) : null;
    } catch (error) {
      this.logger.error(`Error getting user from cache: ${error.message}`);
      return null;
    }
  }

  async setUser(user: User): Promise<void> {
    try {
      const userString = JSON.stringify(user);
      await Promise.all([
        this.redis.set(`user:id:${user._id}`, userString, 'EX', this.ttl),
        this.redis.set(`user:email:${user.email}`, userString, 'EX', this.ttl)
      ]);
    } catch (error) {
      this.logger.error(`Error setting user in cache: ${error.message}`);
    }
  }

  async invalidateUser(userId: string, email: string): Promise<void> {
    try {
      await Promise.all([
        this.redis.del(`user:id:${userId}`),
        this.redis.del(`user:email:${email}`)
      ]);
    } catch (error) {
      this.logger.error(`Error invalidating user cache: ${error.message}`);
    }
  }
}