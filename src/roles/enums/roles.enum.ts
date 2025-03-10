import { registerEnumType } from '@nestjs/graphql';

export enum UserRole {
  // Rôles de Base
  ADMIN = 'ADMIN',
  USER = 'user',
  
  // Rôles de Validation
  NOTAIRE = 'NOTAIRE',
  GEOMETRE = 'GEOMETRE',
  EXPERT_JURIDIQUE = 'EXPERT_JURIDIQUE'
}

registerEnumType(UserRole, {
  name: 'UserRole',
  description: 'Rôles disponibles dans l\'application',
});