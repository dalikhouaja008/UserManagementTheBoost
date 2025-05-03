import { ObjectType, Field, registerEnumType } from '@nestjs/graphql';
import { Prop } from '@nestjs/mongoose';
import { Resource } from '../enums/resource.enum';
import { Action } from '../enums/action.enum';

@ObjectType()
export class Permission {
    @Field(() => Resource)
    @Prop({ type: String, enum: Resource, required: true })
    resource: Resource;

    @Field(() => [Action])
    @Prop({ type: [String], enum: Action, required: true })
    actions: Action[];
}

registerEnumType(Resource, {
    name: 'Resource',
    description: 'Les ressources disponibles dans l\'application',
  });
  
  registerEnumType(Action, {
    name: 'Action',
    description: 'Les actions possibles sur les ressources',
  });