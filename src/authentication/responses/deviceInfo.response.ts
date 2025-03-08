import { ObjectType, Field } from '@nestjs/graphql';


@ObjectType()
export class DeviceInfo {
  @Field(() => String, { nullable: true })
  userAgent?: string;

  @Field(() => String, { nullable: true })
  ip?: string;

  @Field(() => String, { nullable: true })
  device?: string;

  @Field(() => String, { nullable: true })
  browser?: string;

  @Field(() => String, { nullable: true })
  os?: string;
}
