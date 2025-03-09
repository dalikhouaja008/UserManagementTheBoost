import { ObjectType, Field } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
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

@Schema({ timestamps: true })
@ObjectType()
export class Role extends Document {
    @Field()
    @Prop({ required: true, unique: true })
    name: string;

    @Field(() => [Permission])
    @Prop({ type: [{ resource: String, actions: [String] }], required: true })
    permissions: Permission[];
}

export const RoleSchema = SchemaFactory.createForClass(Role);

