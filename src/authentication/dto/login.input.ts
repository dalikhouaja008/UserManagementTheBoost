import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, MinLength, IsOptional, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { DeviceInfoInput } from './device-info.input';
@InputType('LoginInput')
export class LoginInput {
  @Field(() => String)
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @Field(() => String)
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @Field(() => DeviceInfoInput, { nullable: true })
  @IsOptional()
  @ValidateNested()
  @Type(() => DeviceInfoInput)
  deviceInfo?: DeviceInfoInput;
}