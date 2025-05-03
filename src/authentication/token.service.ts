import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { nanoid } from 'nanoid';
import { SessionConfig } from 'src/config/session';
import { RedisCacheService } from 'src/redis/redis-cahce.service';



@Injectable()
export class TokenService {
    private readonly logger = new Logger(TokenService.name);
    private readonly TOKEN_PREFIX = 'token:';
    private readonly SESSION_PREFIX = 'session:';
    private readonly TEMP_TOKEN_PREFIX = 'temp_token:';
    private readonly FAILED_ATTEMPTS_PREFIX = '2fa_failed:';
    private readonly FAILED_ATTEMPTS_TTL = 1800; // 30 minutes en secondes
    public readonly MAX_FAILED_ATTEMPTS = 5; // Nombre maximum de tentatives échouées
    private readonly USER_SESSIONS_PREFIX = 'user_sessions:';
    constructor(private readonly redisCacheService: RedisCacheService) { }

    async storeUserToken(
        userId: string,
        tokenData: Omit<TokenData, 'lastActive'>
    ): Promise<string> {
        try {
            const sessionId = `${Date.now()}_${nanoid(6)}`;
            const sessionKey = `${this.SESSION_PREFIX}${userId}:${sessionId}`;
            const userTokenKey = `${this.TOKEN_PREFIX}${userId}`;

            const sessionData: TokenData = {
                ...tokenData,
                lastActive: new Date()
            };

            // 1. Stocker les détails de la session
            await this.redisCacheService.set(
                sessionKey,
                sessionData,
                86400 // 24 heures
            );

            // 2. Ajouter le sessionId à l'ensemble des sessions de l'utilisateur
            await this.redisCacheService.sadd(
                `${this.USER_SESSIONS_PREFIX}${userId}`,
                sessionId
            );

            // 3. Stocker une référence pour le refresh token
            if (tokenData.refreshToken) {
                await this.redisCacheService.set(
                    `refresh_token:${tokenData.refreshToken}`,
                    { userId, sessionId },
                    259200 // 3 jours
                );
            }

            return sessionId;
        } catch (error) {
            this.logger.error(`Error storing token for user ${userId}:`, error);
            throw new InternalServerErrorException('Failed to store session data');
        }
    }

    async storeTempToken(userId: string, tempTokenData: Omit<TempTokenData, 'createdAt'>) {
        const key = `${this.TEMP_TOKEN_PREFIX}${userId}`;
        const data: TempTokenData = {
            ...tempTokenData,
            createdAt: new Date()
        };

        await this.redisCacheService.set(key, data, 300); // 5 minutes
    }
    async getTempToken(userId: string): Promise<any> {
        try {
            return await this.redisCacheService.get(
                `${this.TEMP_TOKEN_PREFIX}${userId}`
            );
        } catch (error) {
            this.logger.error(`Error getting temp token for user ${userId}:`, error);
            return null;
        }
    }

    async deleteTempToken(userId: string): Promise<void> {
        try {
            await this.redisCacheService.del(`${this.TEMP_TOKEN_PREFIX}${userId}`);
        } catch (error) {
            this.logger.error(`Error deleting temp token for user ${userId}:`, error);
            throw error;
        }
    }


    async validateToken(userId: string, token: string): Promise<boolean> {
        try {
            const userTokenKey = `${this.TOKEN_PREFIX}${userId}`;
            const userSessions = await this.redisCacheService.get(userTokenKey);

            if (!userSessions) {
                return false;
            }

            // Vérifier si le token existe dans une des sessions
            return Object.values(userSessions).some(
                (session: any) => session.accessToken === token
            );
        } catch (error) {
            this.logger.error(`Error validating token for user ${userId}:`, error);
            return false;
        }
    }

    async getUserSessions(userId: string) {
        const key = `${this.TOKEN_PREFIX}${userId}`;
        return await this.redisCacheService.get(key);
    }

    async updateSessionActivity(userId: string, sessionId: string): Promise<void> {
        try {
            const sessionKey = `${this.SESSION_PREFIX}${sessionId}`;
            const session = await this.redisCacheService.get(sessionKey);

            if (session) {
                session.lastActive = new Date();
                await this.redisCacheService.set(sessionKey, session, 86400); // 24 heures
            }
        } catch (error) {
            this.logger.error(`Error updating session activity for ${sessionId}:`, error);
        }
    }

    async invalidateSession(userId: string, sessionId: string): Promise<void> {
        try {
            // Supprimer la session spécifique
            const sessionKey = `${this.SESSION_PREFIX}${sessionId}`;
            const userTokenKey = `${this.TOKEN_PREFIX}${userId}`;

            await this.redisCacheService.del(sessionKey);

            // Mettre à jour la liste des sessions
            const userSessions = await this.redisCacheService.get(userTokenKey);
            if (userSessions) {
                delete userSessions[sessionId];
                if (Object.keys(userSessions).length > 0) {
                    await this.redisCacheService.set(userTokenKey, userSessions, 604800);
                } else {
                    await this.redisCacheService.del(userTokenKey);
                }
            }
        } catch (error) {
            this.logger.error(`Error invalidating session ${sessionId}:`, error);
            throw new InternalServerErrorException('Failed to invalidate session');
        }
    }

    async invalidateAllSessions(userId: string): Promise<void> {
        try {
            const userTokenKey = `${this.TOKEN_PREFIX}${userId}`;
            const userSessions = await this.redisCacheService.get(userTokenKey);

            if (userSessions) {
                // Supprimer toutes les sessions
                await Promise.all(
                    Object.keys(userSessions).map(sessionId =>
                        this.redisCacheService.del(`${this.SESSION_PREFIX}${sessionId}`)
                    )
                );

                // Supprimer la liste des sessions
                await this.redisCacheService.del(userTokenKey);
            }
        } catch (error) {
            this.logger.error(`Error invalidating all sessions for user ${userId}:`, error);
            throw new InternalServerErrorException('Failed to invalidate all sessions');
        }
    }

    async findSessionByRefreshToken(refreshToken: string) {
        try {
            // Parcourir toutes les sessions pour trouver le refresh token
            const allSessions = await this.redisCacheService.keys(`${this.TOKEN_PREFIX}*`);

            for (const sessionKey of allSessions) {
                const session = await this.redisCacheService.get(sessionKey);
                if (session && session.refreshToken === refreshToken) {
                    return {
                        userId: sessionKey.replace(this.TOKEN_PREFIX, ''),
                        ...session
                    };
                }
            }

            return null;
        } catch (error) {
            this.logger.error('Error finding session by refresh token:', error);
            return null;
        }
    }

    async storeUserTokenWithRefresh(
        userId: string,
        accessToken: string,
        refreshToken: string,
        deviceInfo: any
    ) {
        const sessionData = {
            accessToken,
            refreshToken,
            deviceInfo,
            loginTime: new Date(),
            lastActive: new Date()
        };

        const sessionId = await this.storeUserToken(userId, sessionData);

        // Stocker une référence inversée pour la recherche rapide par refresh token
        await this.redisCacheService.set(
            `refresh_token:${refreshToken}`,
            { userId, sessionId },
            259200 // 3 jours
        );

        return sessionId;
    }

    async invalidateRefreshToken(refreshToken: string) {
        try {
            const tokenData = await this.redisCacheService.get(`refresh_token:${refreshToken}`);
            if (tokenData) {
                await Promise.all([
                    this.redisCacheService.del(`refresh_token:${refreshToken}`),
                    this.invalidateSession(tokenData.userId, tokenData.sessionId)
                ]);
            }
        } catch (error) {
            this.logger.error('Error invalidating refresh token:', error);
        }
    }

    async incrementFailedAttempts(userId: string): Promise<number> {
        try {
            const key = `${this.FAILED_ATTEMPTS_PREFIX}${userId}`;
            const currentAttempts = await this.redisCacheService.get(key) || 0;
            const newAttempts = Number(currentAttempts) + 1;

            await this.redisCacheService.set(
                key,
                newAttempts,
                this.FAILED_ATTEMPTS_TTL
            );

            // Si le nombre maximum de tentatives est atteint
            if (newAttempts >= this.MAX_FAILED_ATTEMPTS) {
                // Vous pouvez implémenter ici une logique de blocage temporaire
                this.logger.warn(`User ${userId} has reached maximum failed 2FA attempts`);
            }

            return newAttempts;
        } catch (error) {
            this.logger.error(`Error incrementing failed attempts for user ${userId}:`, error);
            throw error;
        }
    }
    async resetFailedAttempts(userId: string): Promise<void> {
        try {
            await this.redisCacheService.del(`${this.FAILED_ATTEMPTS_PREFIX}${userId}`);
        } catch (error) {
            this.logger.error(`Error resetting failed attempts for user ${userId}:`, error);
            throw error;
        }
    }
    async getFailedAttempts(userId: string): Promise<number> {
        try {
            const attempts = await this.redisCacheService.get(
                `${this.FAILED_ATTEMPTS_PREFIX}${userId}`
            );
            return Number(attempts) || 0;
        } catch (error) {
            this.logger.error(`Error getting failed attempts for user ${userId}:`, error);
            return 0;
        }
    }
    async isUserBlocked(userId: string): Promise<boolean> {
        try {
            const attempts = await this.getFailedAttempts(userId);
            return attempts >= this.MAX_FAILED_ATTEMPTS;
        } catch (error) {
            this.logger.error(`Error checking if user ${userId} is blocked:`, error);
            return false;
        }
    }
    /**
   * Récupérer une session spécifique
   */
    async getSession(userId: string, sessionId: string): Promise<any> {
        try {
            const session = await this.redisCacheService.get(
                `${this.SESSION_PREFIX}${userId}:${sessionId}`
            );
            if (session) {
                return {
                    ...session,
                    id: sessionId,
                    sessionId: sessionId
                };
            }
            return null;
        } catch (error) {
            this.logger.error(`Error getting session for user ${userId}:`, error);
            return null;
        }
    }
    /**
* Supprimer une session spécifique
*/
    async deleteSession(userId: string, sessionId: string): Promise<void> {
        try {
            // Supprimer la session
            await this.redisCacheService.del(
                `${this.SESSION_PREFIX}${userId}:${sessionId}`
            );

            // Mettre à jour la liste des sessions de l'utilisateur
            await this.redisCacheService.srem(
                `${this.USER_SESSIONS_PREFIX}${userId}`,
                sessionId
            );
        } catch (error) {
            this.logger.error(`Error deleting session for user ${userId}:`, error);
            throw error;
        }
    }
    /**
   * Supprimer toutes les sessions d'un utilisateur
   */
    async deleteAllSessions(userId: string): Promise<void> {
        try {
            // Récupérer tous les IDs de session
            const sessionIds = await this.redisCacheService.smembers(
                `${this.USER_SESSIONS_PREFIX}${userId}`
            );

            // Supprimer chaque session
            const deletionPromises = sessionIds.map(sessionId =>
                this.redisCacheService.del(`${this.SESSION_PREFIX}${userId}:${sessionId}`)
            );

            await Promise.all(deletionPromises);

            // Supprimer la liste des sessions
            await this.redisCacheService.del(`${this.USER_SESSIONS_PREFIX}${userId}`);
        } catch (error) {
            this.logger.error(`Error deleting all sessions for user ${userId}:`, error);
            throw error;
        }
    }
    /**
* Récupérer toutes les sessions actives d'un utilisateur
*/
    async getAllSessions(userId: string): Promise<any[]> {
        try {
            // Récupérer tous les IDs de session
            const sessionIds = await this.redisCacheService.smembers(
                `${this.USER_SESSIONS_PREFIX}${userId}`
            );

            // Récupérer les détails de chaque session
            const sessions = await Promise.all(
                sessionIds.map(async sessionId => {
                    const session = await this.getSession(userId, sessionId);
                    if (session) {
                        return {
                            ...session,
                            id: sessionId, // Ajout explicite de l'id
                            sessionId: sessionId // Garder sessionId pour compatibilité
                        };
                    }
                    return null;
                })
            );

            // Filtrer les sessions null (expirées) et s'assurer que l'id est présent
            return sessions.filter(session => session !== null);
        } catch (error) {
            this.logger.error(`Error getting all sessions for user ${userId}:`, error);
            return [];
        }
    }

    /**
     * Mettre à jour le timestamp de dernière activité d'une session
     */
    async updateSessionLastActive(userId: string, sessionId: string): Promise<void> {
        try {
            const session = await this.getSession(userId, sessionId);
            if (session) {
                session.lastActive = new Date();
                await this.redisCacheService.set(
                    `${this.SESSION_PREFIX}${userId}:${sessionId}`,
                    session,
                    86400 // TTL de 24 heures
                );
            }
        } catch (error) {
            this.logger.error(`Error updating session last active time:`, error);
        }
    }

    // Révoquer une session spécifique
    async revokeSession(userId: string, sessionId: string): Promise<void> {
        // Supprimer la session spécifique
        await this.redisCacheService.del(`${this.SESSION_PREFIX}${userId}:${sessionId}`);
        // Retirer l'ID de session de l'ensemble des sessions
        await this.redisCacheService.srem(
            `${this.USER_SESSIONS_PREFIX}${userId}`,
            sessionId
        );
    }

    // Révoquer toutes les sessions
    async revokeAllSessions(userId: string): Promise<void> {
        const sessionIds = await this.redisCacheService.smembers(
            `${this.USER_SESSIONS_PREFIX}${userId}`
        );

        // Supprimer toutes les sessions individuelles
        await Promise.all(
            sessionIds.map(sessionId =>
                this.redisCacheService.del(`${this.SESSION_PREFIX}${userId}:${sessionId}`)
            )
        );

        // Supprimer l'ensemble des sessions
        await this.redisCacheService.del(`${this.USER_SESSIONS_PREFIX}${userId}`);
    }
    async updateLastActive(userId: string, sessionId: string): Promise<void> {
        const session = await this.getSession(userId, sessionId);
        if (session) {
            session.lastActive = new Date();
            await this.redisCacheService.set(
                `${this.SESSION_PREFIX}${userId}:${sessionId}`,
                session,
                SessionConfig.SESSION_TTL
            );
        }
    }




}