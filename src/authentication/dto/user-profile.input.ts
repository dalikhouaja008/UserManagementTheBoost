// src/authentication/dto/user-profile.input.ts
import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsString, IsOptional, MinLength, Matches, IsPhoneNumber } from 'class-validator';

@InputType()
export class UserProfileInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'Username must be at least 3 characters long' })
  username?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsEmail({}, { message: 'Invalid email address' })
  email?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsPhoneNumber('TN', { message: 'Invalid phone number format' })
  phoneNumber?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  @Matches(/^0x[a-fA-F0-9]{40}$/, { message: 'Invalid Ethereum address format' })
  publicKey?: string;
}