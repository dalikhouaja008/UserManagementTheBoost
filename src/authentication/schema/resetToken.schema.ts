import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ timestamps: true })
@ObjectType() // Décorateur GraphQL pour définir un type d'objet
export class ResetToken extends Document {
  @Field(() => ID) // Décorateur GraphQL pour exposer le champ
  _id: mongoose.Types.ObjectId;

  @Prop({ required: true, type: mongoose.Types.ObjectId })
  @Field(() => ID, { description: "L'ID de l'utilisateur associé" }) // Décorateur GraphQL
  userId: mongoose.Types.ObjectId;

  @Prop({ required: true })
  @Field(() => String, { description: 'Le token de réinitialisation' }) // Décorateur GraphQL
  token: string;

  @Prop({ required: true })
  @Field(() => Date, { description: 'La date d\'expiration du token' }) // Décorateur GraphQL
  expiryDate: Date;

  @Prop({ required: true })
  @Field(() => String, { description: "L'email associé au token" }) // Décorateur GraphQL
  email: string;

  @Prop({ default: false })
  @Field(() => Boolean, { description: 'Indique si le token a été utilisé' }) // Décorateur GraphQL
  used: boolean;

  @Field(() => Date, { description: 'La date de création du token' }) // Décorateur GraphQL
  createdAt: Date;

  @Field(() => Date, { description: 'La date de mise à jour du token' }) // Décorateur GraphQL
  updatedAt: Date;

  @Prop({ required: false })
@Field(() => String, { description: "Phone number associated with the reset token", nullable: true })
phoneNumber?: string;

}

export const ResetTokenSchema = SchemaFactory.createForClass(ResetToken);

