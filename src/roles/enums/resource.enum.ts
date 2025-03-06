import { registerEnumType } from "@nestjs/graphql";


export enum Resource {
  // Resources User Management
  USERS = 'users',
  ROLES = 'roles',
  AUTH = 'auth',
  SETTINGS = 'settings',
  
  // Resources Land Service
  LAND = 'land',
  LAND_VALIDATION = 'land_validation',
  LAND_DOCUMENTS = 'land_documents',
  LAND_HISTORY = 'land_history',
  
  // Resources Communes
  NOTIFICATIONS = 'notifications',
  DOCUMENTS = 'documents',
}

registerEnumType(Resource, {
  name: 'Resource', // Nom qui sera utilisé dans le schéma GraphQL
  description: 'Resources disponibles dans le service user-management', // Optionnel, mais utile pour la documentation
});