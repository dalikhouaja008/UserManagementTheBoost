import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEthereumAddress } from 'class-validator';
import { Document, Types } from 'mongoose';
import { UserRole } from 'src/roles/enums/roles.enum';
import { Permission } from 'src/roles/schemas/permission.schema';




export type UserDocument = User & Document;

@Schema({ timestamps: true })
@ObjectType()
export class User  extends Document {
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
  @IsEthereumAddress()
  publicKey?: string;

  @Prop({
    type: String,
    enum: Object.values(UserRole),
    set: (role: string) => role.toUpperCase(),
    default: UserRole.USER
  })
  role: string;

  @Field(() => [Permission])
  permissions?: Permission[];

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

  @Prop({ required: false, unique: true })
  @Field(() => String, {

    description: "Numéro de téléphone de l'utilisateur",
    nullable: true,
  })
  phoneNumber?: string;

}

export const UserSchema = SchemaFactory.createForClass(User);