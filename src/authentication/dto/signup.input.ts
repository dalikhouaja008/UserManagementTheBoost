// src/authentication/dto/signup.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';

@InputType()
export class UserInput {
  @Field(() => String, { description: "Nom d'utilisateur" })
  @IsString()
  username: string;

  @Field(() => String, { description: "Adresse e-mail de l'utilisateur" })
  @IsEmail()
  email: string;

  @Field(() => String, { description: "Mot de passe de l'utilisateur" })
  @IsString()
  @MinLength(6)
  password: string;

  @Field(() => String, { 
    nullable: true, 
    description: "Clé publique de la wallet de l'utilisateur" 
  })
  @IsOptional()
  @IsString()
  publicKey?: string;

  @Field(() => String, { 
    nullable: true, 
    description: "Rôle de l'utilisateur (par exemple, 'user', 'admin')" 
  })
  @IsOptional()
  role?: string;

  @Field(() => String, { 
    nullable: true, 
    description: "Numéro de téléphone de l'utilisateur" 
  })
  @IsOptional()
  phoneNumber?: string;

  @Field(() => String, { 
    nullable: true, 
    description: "Secret pour l'authentification à deux facteurs" 
  })
  @IsOptional()
  twoFactorSecret?: string;

  @Field(() => Boolean, { 
    defaultValue: false, 
    description: "Indique si l'utilisateur est vérifié" 
  })
  @IsOptional()
  isVerified?: boolean;
}