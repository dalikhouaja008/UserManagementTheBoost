import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';

@Schema({ timestamps: true })
@ObjectType()
export class User {
  @Field(() => ID)
  _id: Types.ObjectId;

  @Prop({ required: true, unique: true })
  @Field(() => String, { description: "Nom d'utilisateur" })
  username: string;

  @Prop({ required: true, unique: true })
  @Field(() => String, { description: "Adresse e-mail de l'utilisateur" })
  email: string;

  @Prop({ required: true })
  @Field(() => String, { description: "Mot de passe de l'utilisateur" })
  password: string;

  @Prop()
  @Field(() => String, {
    description: "Secret pour l'authentification à deux facteurs",
    nullable: true,
  })
  twoFactorSecret?: string;

  @Prop({ default: false })
  @Field(() => Boolean, {
    description: "Indique si l'utilisateur a activé la 2FA",
    defaultValue: false,
  })
  isTwoFactorEnabled: boolean;

  @Prop({ required: false, unique: true, sparse: true }) // Add sparse to allow null values
  @Field(() => String, {
    description: "Numéro de téléphone de l'utilisateur",
    nullable: true,
  })
  phoneNumber?: string;

  @Field(() => Date, { description: 'Date de création du compte' })
  createdAt: Date;

  @Field(() => Date, { description: 'Date de mise à jour du compte' })
  updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);