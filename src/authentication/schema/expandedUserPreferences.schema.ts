// src/authentication/schema/expandedUserPreferences.schema.ts
import { ObjectType, Field, ID, registerEnumType } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

export enum NotificationType {
  LAND_MATCHES = 'LAND_MATCHES',
  ACCOUNT_CHANGES = 'ACCOUNT_CHANGES',
  SECURITY_ALERTS = 'SECURITY_ALERTS',
  TRANSACTION_UPDATES = 'TRANSACTION_UPDATES',
  DOCUMENT_UPDATES = 'DOCUMENT_UPDATES',
  MARKETING = 'MARKETING'
}

registerEnumType(NotificationType, {
  name: 'NotificationType',
  description: 'Types of notifications a user can receive',
});

@Schema({ timestamps: true })
@ObjectType()
export class NotificationPreferences extends Document {
  @Prop({ type: Boolean, default: true })
  @Field(() => Boolean, { description: 'Email notifications enabled' })
  emailEnabled: boolean;
  
  @Prop({ type: Boolean, default: false })
  @Field(() => Boolean, { description: 'SMS notifications enabled' })
  smsEnabled: boolean;
  
  @Prop({ type: Boolean, default: true })
  @Field(() => Boolean, { description: 'Push notifications enabled' })
  pushEnabled: boolean;
  
  @Prop({ type: [String], enum: NotificationType, default: Object.values(NotificationType) })
  @Field(() => [NotificationType], { description: 'Types of notifications to receive' })
  enabledTypes: NotificationType[];
  
  @Prop({ type: String, default: 'DAILY' })
  @Field(() => String, { description: 'Notification frequency: INSTANT, DAILY, WEEKLY' })
  frequency: string;
}

const NotificationPreferencesSchema = SchemaFactory.createForClass(NotificationPreferences);

@Schema({ timestamps: true })
@ObjectType()
export class ExpandedUserPreferences extends Document {
  // Existing fields
  @Field(() => ID)
  _id: MongooseSchema.Types.ObjectId;

  @Prop({ required: true, type: MongooseSchema.Types.ObjectId, ref: 'User' })
  @Field(() => ID, { description: 'User ID associated with these preferences' })
  userId: MongooseSchema.Types.ObjectId;

  @Prop({ required: true, type: [String] })
  @Field(() => [String], { description: 'Preferred land types' })
  preferredLandTypes: string[];

  @Prop({ required: true, default: 0 })
  @Field(() => Number, { description: 'Minimum price range' })
  minPrice: number;

  @Prop({ required: true, default: 1000000 })
  @Field(() => Number, { description: 'Maximum price range' })
  maxPrice: number;

  @Prop({ type: [String], default: [] })
  @Field(() => [String], { description: 'Preferred locations' })
  preferredLocations: string[];

  @Prop({ required: true, default: 50 })
  @Field(() => Number, { description: 'Maximum distance in kilometers' })
  maxDistanceKm: number;

  // New notification preferences
  @Prop({ type: NotificationPreferencesSchema, default: {} })
  @Field(() => NotificationPreferences, { description: 'Notification preferences' })
  notifications: NotificationPreferences;

  @Prop({ required: true })
  @Field(() => Date, { description: 'Last update timestamp' })
  lastUpdated: Date;

  @Field(() => Date, { description: 'Created date' })
  createdAt: Date;

  @Field(() => Date, { description: 'Updated date' })
  updatedAt: Date;
}

export const ExpandedUserPreferencesSchema = SchemaFactory.createForClass(ExpandedUserPreferences);