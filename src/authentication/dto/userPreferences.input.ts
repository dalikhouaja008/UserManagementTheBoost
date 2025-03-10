import { InputType, Field, Float } from '@nestjs/graphql';
import { IsArray, IsBoolean, IsEnum, IsNumber, IsOptional, IsString, Min, Max } from 'class-validator';
import { LandType } from '../schema/userPreferences.schema';

@InputType()
export class UserPreferencesInput {
  @Field(() => [String], { description: 'Preferred land types' })
  @IsArray()
  @IsEnum(LandType, { each: true })
  preferredLandTypes: LandType[];

  @Field(() => Float, { description: 'Minimum price range', defaultValue: 0 })
  @IsNumber()
  @Min(0)
  minPrice: number = 0;

  @Field(() => Float, { description: 'Maximum price range', defaultValue: 1000000 })
  @IsNumber()
  @Min(0)
  maxPrice: number = 1000000;

  @Field(() => [String], { description: 'Preferred locations', defaultValue: [] })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  preferredLocations: string[] = [];

  @Field(() => Float, { description: 'Maximum distance in kilometers', defaultValue: 50 })
  @IsNumber()
  @Min(0)
  @Max(500)
  maxDistanceKm: number = 50;

  @Field(() => Boolean, { description: 'Whether notifications are enabled', defaultValue: true })
  @IsBoolean()
  notificationsEnabled: boolean = true;
}