// src/config/session.ts
export const SessionConfig = {
  MAX_SESSIONS_PER_USER: 3,  // Limite à 3 sessions simultanées par utilisateur
  SESSION_TTL: 86400,        // 24 heures en secondes
  INACTIVE_TIMEOUT: 3600,    // 1 heure d'inactivité avant déconnexion
  RETRY_ATTEMPTS: 3,        // Nombre de tentatives de reconnexion pour Redis
  RETRY_DELAY: 1000         // Délai (ms) entre les tentatives de reconnexion pour Redis
};  