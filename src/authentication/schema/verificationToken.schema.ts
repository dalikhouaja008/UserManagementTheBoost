import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ timestamps: true })
@ObjectType()
export class VerificationToken extends Document {
  @Field(() => ID)
  _id: mongoose.Types.ObjectId;

  @Prop({ required: true, type: mongoose.Types.ObjectId })
  @Field(() => ID, { description: "The ID of the user associated with this token" })
  userId: mongoose.Types.ObjectId;

  @Prop({ required: true })
  @Field(() => String, { description: "The verification token" })
  token: string;

  @Prop({ required: true })
  @Field(() => Date, { description: "The expiration date of the token" })
  expiryDate: Date;

  @Prop({ required: true })
  @Field(() => String, { description: "The email address associated with this token" })
  email: string;

  @Prop({ default: false })
  @Field(() => Boolean, { description: "Indicates if the token has been used" })
  used: boolean;

  @Field(() => Date, { description: "When the token was created" })
  createdAt: Date;

  @Field(() => Date, { description: "When the token was last updated" })
  updatedAt: Date;
}

export const VerificationTokenSchema = SchemaFactory.createForClass(VerificationToken);