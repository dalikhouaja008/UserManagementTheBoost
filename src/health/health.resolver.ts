import { Resolver, Query, ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class HealthCheck {
  @Field()
  status: string;

  @Field()
  service: string;

  @Field()
  timestamp: string;
}

@Resolver(() => HealthCheck)
export class HealthResolver {
  @Query(() => HealthCheck)
  healthCheck(): HealthCheck {
    return {
      status: 'ok',
      service: 'user-management',
      timestamp: new Date().toISOString()
    };
  }
}