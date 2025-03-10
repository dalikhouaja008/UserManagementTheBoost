import { ObjectType, Field } from '@nestjs/graphql';
import { User } from '../schema/user.schema';
import { DeviceInfo } from './deviceInfo.response';
import { Permission } from 'src/roles/schemas/role.schema';


@ObjectType()
export class LoginResponse {
  @Field(() => String, { nullable: true, description: "JWT Access Token" })
  accessToken: string;

  @Field(() => String, { nullable: true, description: "JWT Refresh Token" })
  refreshToken: string;

  @Field(() => Boolean, { description: "Indique si la 2FA est requise" })
  requiresTwoFactor: boolean;

  @Field({ nullable: true ,description: "token générer lors de la validation 2FA"  })
  tempToken?: string;

  @Field(() => User, { nullable: true , description: "Informations de l'utilisateur" })
  user: User;
  @Field(() => String, { nullable: true, description: "ID de la session" })
  sessionId?: string;

  @Field(() => DeviceInfo, { nullable: true, description: "Informations sur l'appareil" })
  deviceInfo?: DeviceInfo;
  @Field(() => [Permission], { 
    nullable: true, 
    description: "Liste des permissions associées au rôle de l'utilisateur" 
  })
  permissions?: Permission[];
}