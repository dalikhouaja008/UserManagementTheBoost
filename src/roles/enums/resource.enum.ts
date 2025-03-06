import { registerEnumType } from "@nestjs/graphql";


export enum Resource {
  USERS = 'users',
  SETTINGS = 'settings',
  ROLES = 'roles',
  AUTHENTICATION = 'authentication',
  AUTH = "auth"
}

registerEnumType(Resource, {
  name: 'Resource', // Nom qui sera utilisé dans le schéma GraphQL
  description: 'Resources disponibles dans le service user-management', // Optionnel, mais utile pour la documentation
});