import { ObjectType, Field } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

import { Permission } from './permission.schema';


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


export { Permission };
