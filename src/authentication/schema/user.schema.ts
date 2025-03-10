import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { UserRole } from 'src/roles/enums/roles.enum';

export type UserDocument = User & Document;

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
    description: "Indique si l'utilisateur a activé l'authentification à deux facteurs",
    defaultValue: false,
  })
  isTwoFactorEnabled: boolean;

  @Prop()
  @Field(() => String, {
    description: "Clé publique de la wallet de l'utilisateur",
    nullable: true,
  })
  publicKey?: string;

  @Prop({ type: String, enum: UserRole, default: UserRole.USER }) 
  @Field(() => String, {
    description: "Rôle de l'utilisateur (par exemple, 'user', 'admin')",
    nullable: true,
  })
  role?: string;

  @Prop({ default: false })
  @Field(() => Boolean, {
    description: "Indique si l'utilisateur est vérifié",
    defaultValue: false,
  })
  isVerified: boolean;

  @Field(() => Date, { description: 'Date de création du compte' })
  createdAt: Date;

  @Field(() => Date, { description: 'Date de mise à jour du compte' })
  updatedAt: Date;

  @Prop({ required: false, unique: true, sparse: true })
  @Field(() => String, {
    description: "Numéro de téléphone de l'utilisateur",
    nullable: true,
  })
  phoneNumber?: string;

  @Prop({ type: Types.ObjectId, ref: 'UserPreferences' })
  @Field(() => ID, { 
    description: "ID des préférences de l'utilisateur", 
    nullable: true
  })
  preferences?: Types.ObjectId;
}

export const UserSchema = SchemaFactory.createForClass(User);