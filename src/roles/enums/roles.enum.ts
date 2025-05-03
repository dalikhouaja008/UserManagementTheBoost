import { registerEnumType } from '@nestjs/graphql';

export enum UserRole {
  // Rôles de Base
  ADMIN = 'ADMIN',
  USER = 'USER',
  
  // Rôles de Validation
  NOTAIRE = 'NOTAIRE',
  GEOMETRE = 'GEOMETRE',
  EXPERT_JURIDIQUE = 'EXPERT_JURIDIQUE'
}

registerEnumType(UserRole, {
  name: 'UserRole',
  description: 'Rôles disponibles dans l\'application',
});

// Fonction utilitaire pour vérifier si un rôle est un rôle de validateur
export const isValidatorRole = (role: string): boolean => {
  return [
    UserRole.NOTAIRE,
    UserRole.GEOMETRE,
    UserRole.EXPERT_JURIDIQUE
  ].includes(role as UserRole);
};
export const isAdminRole = (role: string): boolean => role === UserRole.ADMIN;
export const isBaseUserRole = (role: string): boolean => role === UserRole.USER;