import { InputType, Field } from '@nestjs/graphql';
import { IsString, MinLength } from 'class-validator';

@InputType()
export class ResetPasswordInput {
  @Field(() => String)
  @IsString()
  token: string;

  @Field(() => String)
  @IsString()
  @MinLength(8)
  newPassword: string;
}