import { registerEnumType } from '@nestjs/graphql';

export enum UserRole {
  ADMIN = 'ADMIN',
  USER = 'USER',
  NOTAIRE = 'NOTAIRE',
  GEOMETRE = 'GEOMETRE',
  EXPERT_JURIDIQUE = 'EXPERT_JURIDIQUE'
}

registerEnumType(UserRole, {
  name: 'UserRole',
  description: 'Rôles disponibles dans l\'application',
});