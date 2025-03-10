import { Field, ObjectType } from "@nestjs/graphql";

@ObjectType()
export class LogoutResponse {
  @Field(() => Boolean, { description: "Statut de la déconnexion" })
  success: boolean;

  @Field(() => String, { nullable: true, description: "Message de confirmation" })
  message?: string;
}