import { InputType, Field } from '@nestjs/graphql';
import { IsOptional, IsString } from 'class-validator';

@InputType('DeviceInfoInput')
export class DeviceInfoInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  userAgent?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  ip?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  device?: string;
}