import { InputType, Field } from '@nestjs/graphql';
import { IsNotEmpty, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { PermissionInput } from './create-role.input';

@InputType()
export class UpdateRoleInput {
  @Field()
  @IsNotEmpty()
  name: string;

  @Field(() => [PermissionInput])
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PermissionInput)
  permissions: PermissionInput[];
}