import { ObjectType, Field, ID, Float, registerEnumType } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum LandType {
  AGRICULTURAL = 'AGRICULTURAL',
  RESIDENTIAL = 'RESIDENTIAL',
  INDUSTRIAL = 'INDUSTRIAL',
  COMMERCIAL = 'COMMERCIAL',
}

registerEnumType(LandType, {
  name: 'LandType',
  description: 'Types of land properties',
});

@Schema({ timestamps: true })
@ObjectType()
export class UserPreferences extends Document {
  @Field(() => ID)
  _id: MongooseSchema.Types.ObjectId;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'User' })
  @Field(() => ID, { description: 'User ID associated with these preferences' })
  userId: MongooseSchema.Types.ObjectId;

  @Prop({ required: true, type: [String], enum: LandType })
  @Field(() => [LandType], { description: 'Preferred land types' })
  preferredLandTypes: LandType[];

  @Prop({ required: true, default: 0 })
  @Field(() => Float, { description: 'Minimum price range' })
  minPrice: number;

  @Prop({ required: true, default: 1000000 })
  @Field(() => Float, { description: 'Maximum price range' })
  maxPrice: number;

  @Prop({ type: [String], default: [] })
  @Field(() => [String], { description: 'Preferred locations' })
  preferredLocations: string[];

  @Prop({ required: true, default: 50 })
  @Field(() => Float, { description: 'Maximum distance in kilometers' })
  maxDistanceKm: number;

  @Prop({ default: true })
  @Field(() => Boolean, { description: 'Whether notifications are enabled' })
  notificationsEnabled: boolean;

  @Prop({ required: true })
  @Field(() => Date, { description: 'Last update timestamp' })
  lastUpdated: Date;

  @Field(() => Date, { description: 'Created date' })
  createdAt: Date;

  @Field(() => Date, { description: 'Updated date' })
  updatedAt: Date;
}

export const UserPreferencesSchema = SchemaFactory.createForClass(UserPreferences);