import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { nanoid } from 'nanoid';
import { SessionConfig } from 'src/config/session';
import { RedisCacheService } from 'src/redis/redis-cahce.service';
import { TokenData } from './interfaces/tempTokenData.interface';
import { TempTokenData } from './interfaces/tempTokenData.interface';

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
            
            const sessionData: TokenData = {
                ...tokenData,
                lastActive: new Date(),
                sessionId
            };

            // Stocker les détails de la session
            await this.redisCacheService.set(
                sessionKey,
                sessionData,
                SessionConfig.SESSION_TTL || 86400 // 24 heures par défaut
            );

            // Ajouter l'ID de la session à l'ensemble des sessions de l'utilisateur
            await this.redisCacheService.sadd(
                `${this.USER_SESSIONS_PREFIX}${userId}`,
                sessionId
            );

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
    
    async getTempToken(userId: string): Promise<TempTokenData | null> {
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
            // Vérifier toutes les sessions de l'utilisateur
            const sessionIds = await this.redisCacheService.smembers(
                `${this.USER_SESSIONS_PREFIX}${userId}`
            );
            
            for (const sessionId of sessionIds) {
                const session = await this.getSession(userId, sessionId);
                if (session && session.accessToken === token) {
                    return true;
                }
            }
            
            return false;
        } catch (error) {
            this.logger.error(`Error validating token for user ${userId}:`, error);
            return false;
        }
    }

    async getUserSessions(userId: string) {
        return this.getAllSessions(userId);
    }

    async updateSessionActivity(userId: string, sessionId: string): Promise<void> {
        try {
            const sessionKey = `${this.SESSION_PREFIX}${userId}:${sessionId}`;
            const session = await this.redisCacheService.get(sessionKey);

            if (session) {
                session.lastActive = new Date();
                await this.redisCacheService.set(
                    sessionKey, 
                    session, 
                    SessionConfig.SESSION_TTL || 86400
                ); // 24 heures par défaut
            }
        } catch (error) {
            this.logger.error(`Error updating session activity for ${sessionId}:`, error);
        }
    }

    async invalidateSession(userId: string, sessionId: string): Promise<void> {
        await this.deleteSession(userId, sessionId);
    }

    async invalidateAllSessions(userId: string): Promise<void> {
        await this.deleteAllSessions(userId);
    }

    async findSessionByRefreshToken(refreshToken: string): Promise<{ userId: string, deviceInfo: any } | null> {
        try {
            const sessionIds = await this.redisCacheService.keys(`${this.SESSION_PREFIX}*`);
            
            for (const key of sessionIds) {
                const session = await this.redisCacheService.get(key);
                if (session && session.refreshToken === refreshToken) {
                    // Extraire l'userId du format "session:userId:sessionId"
                    const parts = key.split(':');
                    if (parts.length >= 2) {
                        return {
                            userId: parts[1],
                            deviceInfo: session.deviceInfo
                        };
                    }
                }
            }
            
            return null;
        } catch (error) {
            this.logger.error('Error finding session by refresh token:', error);
            return null;
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
    
    async getSession(userId: string, sessionId: string): Promise<TokenData | null> {
        try {
            return await this.redisCacheService.get(
                `${this.SESSION_PREFIX}${userId}:${sessionId}`
            );
        } catch (error) {
            this.logger.error(`Error getting session for user ${userId}:`, error);
            return null;
        }
    }
    
    async deleteSession(userId: string, sessionId: string): Promise<void> {
        try {
            // Supprimer la session
            await this.redisCacheService.del(
                `${this.SESSION_PREFIX}${userId}:${sessionId}`
            );

            // Retirer l'ID de session de l'ensemble des sessions
            await this.redisCacheService.srem(
                `${this.USER_SESSIONS_PREFIX}${userId}`,
                sessionId
            );
        } catch (error) {
            this.logger.error(`Error deleting session for user ${userId}:`, error);
            throw error;
        }
    }
    
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
    
    async getAllSessions(userId: string): Promise<any[]> {
        try {
            // Récupérer tous les IDs de session
            const sessionIds = await this.redisCacheService.smembers(
                `${this.USER_SESSIONS_PREFIX}${userId}`
            );

            // Récupérer les détails de chaque session
            const sessionPromises = sessionIds.map(async sessionId => {
                const session = await this.getSession(userId, sessionId);
                if (session) {
                    return {
                        ...session,
                        sessionId
                    };
                }
                return null;
            });

            const sessions = await Promise.all(sessionPromises);

            // Filtrer les sessions null (expirées)
            return sessions.filter(session => session !== null);
        } catch (error) {
            this.logger.error(`Error getting all sessions for user ${userId}:`, error);
            return [];
        }
    }

    async updateLastActive(userId: string, sessionId: string): Promise<void> {
        try {
            const session = await this.getSession(userId, sessionId);
            if (session) {
                session.lastActive = new Date();
                await this.redisCacheService.set(
                    `${this.SESSION_PREFIX}${userId}:${sessionId}`,
                    session,
                    SessionConfig.SESSION_TTL
                );
            }
        } catch (error) {
            this.logger.error(`Error updating session last active time:`, error);
        }
    }

    // Révoquer une session spécifique
    async revokeSession(userId: string, sessionId: string): Promise<void> {
        await this.deleteSession(userId, sessionId);
    }

    // Révoquer toutes les sessions
    async revokeAllSessions(userId: string): Promise<void> {
        await this.deleteAllSessions(userId);
    }
}