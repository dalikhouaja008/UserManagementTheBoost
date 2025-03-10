import { InputType, Field } from '@nestjs/graphql';
import { Prop } from '@nestjs/mongoose';
import { IsEmail, IsString, IsOptional, IsBoolean, MinLength, IsNotEmpty, IsPhoneNumber } from 'class-validator';

@InputType()
export class UserInput {
  @Field(() => String, { description: "Nom d'utilisateur" })
  @IsString()
  @MinLength(3)
  username: string;

  @Field(() => String, { description: "Adresse e-mail de l'utilisateur" })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @Field(() => String, { description: "Mot de passe de l'utilisateur" })
  @IsString()
  @MinLength(8)
  password: string;

  @Field(() => String, {
    description: "Rôle de l'utilisateur (par exemple, 'user', 'admin')",
    nullable: true,
  })
  @IsOptional()
  @IsString()
  role?: string;

  @Field(() => String, {
    description: "Clé publique de la wallet de l'utilisateur",
    nullable: true,
  })


<<<<<<< HEAD
=======
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsPhoneNumber('TN') // Adjust for your region if needed
  phoneNumber?: string;

  
>>>>>>> c09d11afd1c1706073e2ccd3e475b9de63bf655f
  @IsOptional()
  @IsString()
  publicKey?: string;

  @Field(() => String, {
    description: "Secret pour l'authentification à deux facteurs",
    nullable: true,
  })
  @IsOptional()
  @IsString()
  twoFactorSecret?: string;

  @Field(() => Boolean, {
    description: "Indique si l'utilisateur est vérifié",
    defaultValue: false,
  })
  @IsOptional()
  @IsBoolean()
  isVerified?: boolean;
}