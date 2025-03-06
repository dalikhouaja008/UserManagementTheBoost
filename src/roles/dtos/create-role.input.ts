import { InputType, Field } from '@nestjs/graphql';
import { IsNotEmpty, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { Resource } from '../enums/resource.enum';
import { Action } from '../enums/action.enum';

@InputType()
export class PermissionInput {
  @Field(() => Resource)
  @IsNotEmpty()
  resource: Resource;

  @Field(() => [Action])
  @IsArray()
  @IsNotEmpty()
  actions: Action[];
}

@InputType()
export class CreateRoleInput {
  @Field()
  @IsNotEmpty()
  name: string;

  @Field(() => [PermissionInput])
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PermissionInput)
  permissions: PermissionInput[];
}