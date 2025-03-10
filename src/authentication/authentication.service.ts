import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
  forwardRef,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid/non-secure';
import { MailService } from '../services/mail.service';
import { RolesService } from '../roles/roles.service';
import { ResetToken } from './schema/resetToken.schema';
import { RefreshToken } from './schema/refreshToken.schema';
import { User } from './schema/user.schema';
import { UserInput } from './dto/signup.input';
import { Model, Types } from 'mongoose';
import { LoginInput } from './dto/login.input';
import { TwoFactorAuthService } from './TwoFactorAuth.service';
import { LoginResponse } from './responses/login.response';
import { UserRole } from 'src/roles/enums/roles.enum';
import { Resource } from 'src/roles/enums/resource.enum';
import { Action } from 'src/roles/enums/action.enum';
import { RedisCacheService } from 'src/redis/redis-cahce.service';
import { TokenService } from './token.service';
import { Session } from './dto/session.type';
import * as crypto from 'crypto';
import { TwilioService } from 'src/services/twilio.service';

function generateOtp(): string {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
}

@Injectable()
export class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService,
    @Inject(forwardRef(() => RolesService))
    private rolesService: RolesService,
    private twoFactorAuthService: TwoFactorAuthService,
    private readonly redisCacheService: RedisCacheService,
    private readonly tokenService: TokenService,
    private readonly twilioService: TwilioService
  ) { }
  
  /**
  * Méthode utilitaire pour trouver un utilisateur
  */
  async findUser(
    identifier: string,
    type: 'id' | 'email',
    throwError: boolean = false
  ): Promise<User | null> {
    try {
      // Chercher d'abord dans le cache
      const cachedUser = type === 'id'
        ? await this.redisCacheService.getUserById(identifier)
        : await this.redisCacheService.getUserByEmail(identifier);

      if (cachedUser) {
        this.logger.debug(`User found in cache with ${type}: ${identifier}`);
        return cachedUser;
      }

      // Si pas dans le cache, chercher dans la BD
      const query = type === 'id' ? { _id: identifier } : { email: identifier };
      const user = await this.UserModel.findOne(query);

      if (user) {
        await this.redisCacheService.setUser(user);
        this.logger.debug(`User found in DB and cached with ${type}: ${identifier}`);
        return user;
      }

      if (throwError) {
        throw new NotFoundException(`User not found with ${type}: ${identifier}`);
      }

      return null;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      this.logger.error(`Error finding user with ${type}: ${identifier}`, error);
      if (throwError) {
        throw new NotFoundException(`Error finding user with ${type}: ${identifier}`);
      }
      return null;
    }
  }

  /**
  * Méthode utilitaire pour enregistrer un nouvel utilisateur
  */
  async signup(signupData: UserInput) {
    const { email, username, password, publicKey, twoFactorSecret, role, isVerified, phoneNumber } = signupData;
  
    // Vérifier si l'email existe déjà
    const existingUser = await this.findUser(email, 'email');
    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }
  
    // Vérifier si le numéro de téléphone est déjà utilisé (si fourni)
    if (phoneNumber) {
      const phoneInUse = await this.UserModel.findOne({ phoneNumber });
      if (phoneInUse) {
        throw new BadRequestException('Phone number already in use');
      }
    }
  
    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      // Create with explicit ID assignment
      const newUser = new this.UserModel({
        _id: new Types.ObjectId(), // Explicitly create an ID
        username,
        email,
        password: hashedPassword,
        publicKey: publicKey || null,
        twoFactorSecret: twoFactorSecret || null,
        role: role || UserRole.USER,
        isVerified: isVerified || false,
        phoneNumber: phoneNumber || null,
      });
      
      await newUser.save();
      
      // Mettre le nouvel utilisateur en cache
      await this.redisCacheService.setUser(newUser);
  
      return newUser;
    } catch (error) {
      this.logger.error(`Error creating user: ${error.message}`, error.stack);
      throw new Error(`Failed to create user: ${error.message}`);
    }
  }

  async validateUser(userId: string): Promise<any> {
    // Vérifier d'abord dans le cache
    const cachedUser = await this.redisCacheService.getUserById(userId);
    if (cachedUser) {
      return cachedUser;
    }

    // Si pas dans le cache, chercher dans la BD
    const user = await this.UserModel.findById(userId).exec();
    if (user) {
      // Mettre en cache pour les futures requêtes
      await this.redisCacheService.setUser(user);
    }
    return user ? user : null;
  }

  /**
   * Méthode utilitaire pour se connecter à l'application
   */
  async login(credentials: LoginInput, deviceInfo: any): Promise<LoginResponse> {
    const timestamp = new Date().toISOString();

    try {
      console.log(`[${timestamp}] 🔑 Login attempt for email: ${credentials.email}`);

      const user = await this.findUser(credentials.email, 'email');
      if (!user) {
        throw new UnauthorizedException('Identifiants invalides');
      }

      const isPasswordValid = await bcrypt.compare(
        credentials.password,
        user.password
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Identifiants invalides');
      }

      if (user.isTwoFactorEnabled) {
        console.log(`[${timestamp}] 🔐 2FA is enabled for user: ${user.email}`);

        const tempToken = this.jwtService.sign(
          {
            userId: user._id,
            isTemp: true
          },
          {
            expiresIn: '5m',
            secret: process.env.JWT_SECRET
          }
        );

        // Stocker les informations temporaires selon votre interface TempTokenData
        await this.tokenService.storeTempToken(user._id.toString(), {
          token: tempToken,
          deviceInfo: deviceInfo,
          type: 'twoFactor',
        });

        return {
          requiresTwoFactor: true,
          tempToken,
          accessToken: null,
          refreshToken: null,
          user: user,
          deviceInfo,
          sessionId: null
        };
      }

      const tokens = await this.generateUserTokens(
        user._id,
        false,
        deviceInfo
      );

      return {
        requiresTwoFactor: false,
        tempToken: null,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user,
        deviceInfo,
        sessionId: tokens.sessionId
      };

    } catch (error) {
      console.error(`[${timestamp}] ❌ Login failed:`, error.message);
      throw error;
    }
  }

  /**
  * Méthode utilitaire pour changer le mot de passe de l'utilisateur
  */
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.findUser(userId, 'id', true);

    // Compare the old password with the password in DB
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    // Change user's password et récupérer l'utilisateur mis à jour
    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      { password: newHashedPassword },
      { new: true } // Retourne le document mis à jour
    );

    // Invalider le cache
    await this.redisCacheService.invalidateUser(userId, user.email);

    // Mettre à jour le cache avec le nouvel utilisateur
    if (updatedUser) {
      await this.redisCacheService.setUser(updatedUser);
    }

    return updatedUser;
  }

  async forgotPassword(identifier: string): Promise<void> {
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
    let user;
    
    if (isEmail) {
        user = await this.UserModel.findOne({ email: identifier });
    } else {
        // Normalize phone number format if needed
        let normalizedPhone = identifier.startsWith('+216') ? identifier : `+216${identifier}`;
        user = await this.UserModel.findOne({ phoneNumber: normalizedPhone });
    }

    if (!user) {
        this.logger.warn(`User with ${isEmail ? 'email' : 'phone number'} ${identifier} not found`);
        throw new NotFoundException('User not found');
    }

    const expiryDate = new Date();
    expiryDate.setMinutes(expiryDate.getMinutes() + 15);

    let resetToken: string;
    if (isEmail) {
        resetToken = nanoid(64);
    } else {
        resetToken = generateOtp();
    }

    await this.ResetTokenModel.create({
        token: resetToken,
        userId: user._id,
        expiryDate,
        email: user.email,
        phoneNumber: isEmail ? null : identifier,
    });

    if (isEmail) {
        this.logger.log(`Sending password reset email to ${identifier}`);
        await this.mailService.sendPasswordResetEmail(identifier, resetToken);
    } else {
        this.logger.log(`Sending password reset SMS to ${identifier}`);
        await this.twilioService.sendSms(identifier, `Your OTP code is: ${resetToken}`);
    }

    this.logger.log(`Password reset code sent to ${identifier}`);
  }

  async forgotPasswordSms(phoneNumber: string): Promise<void> {
    // Normalize phone number
    const normalizedPhone = phoneNumber.startsWith('+216') ? phoneNumber : `+216${phoneNumber}`;
    const user = await this.UserModel.findOne({ phoneNumber: normalizedPhone });
  
    if (!user) {
      this.logger.warn(`User with phone number ${normalizedPhone} not found`);
      throw new NotFoundException('User with this phone number not found');
    }
  
    const otp = generateOtp();
    const expiryDate = new Date();
    expiryDate.setMinutes(expiryDate.getMinutes() + 15); // OTP valid for 15 mins
  
    await this.ResetTokenModel.create({
      token: otp,
      userId: user._id,
      expiryDate,
      email: user.email,
      phoneNumber: normalizedPhone,
    });
  
    await this.twilioService.sendSms(normalizedPhone, `Your OTP code is: ${otp}`);
    this.logger.log(`Password reset OTP sent to ${normalizedPhone}`);
  }

  async resetPasswordWithToken(token: string, newPassword: string): Promise<User> {
    const resetToken = await this.ResetTokenModel.findOne({ 
      token,
      used: false,
      expiryDate: { $gt: new Date() }
    });

    if (!resetToken) {
      throw new BadRequestException('Invalid or expired token');
    }

    const user = await this.UserModel.findById(resetToken.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Mark token as used
    resetToken.used = true;
    await resetToken.save();

    // Invalidate user cache
    await this.redisCacheService.invalidateUser(user._id.toString(), user.email);

    return user;
  }

  async verifyCode(identifier: string, code: string): Promise<boolean> {
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);

    const query = isEmail 
        ? { email: identifier } 
        : { phoneNumber: identifier };

    const resetToken = await this.ResetTokenModel.findOne({
        ...query,
        token: code,
        used: false,
        expiryDate: { $gt: new Date() }
    });

    if (!resetToken) {
        this.logger.warn(`Failed OTP verification for ${identifier}`);
        return false;
    }

    resetToken.used = true;
    await resetToken.save();

    return true;
  }

  /**
  * Partie gestion des tokens
  */

  async refreshTokens(refreshToken: string) {
    // Vérifier d'abord dans Redis
    const sessions = await this.tokenService.findSessionByRefreshToken(refreshToken);
    if (!sessions) {
      // Si pas dans Redis, vérifier dans MongoDB (pour la rétrocompatibilité)
      const token = await this.RefreshTokenModel.findOne({
        token: refreshToken,
        expiryDate: { $gte: new Date() },
      });

      if (!token) {
        throw new UnauthorizedException('Refresh Token is invalid');
      }

      // Si trouvé dans MongoDB, migrer vers Redis
      const newTokens = await this.generateUserTokens(
        token.userId.toString(),
        false,
        sessions?.deviceInfo || {
          userAgent: 'default',
          ip: 'unknown',
          device: 'unknown'
        }
      );
      return newTokens;
    }

    // Utiliser les informations du device stockées dans la session
    return this.generateUserTokens(
      sessions.userId,
      false,
      sessions.deviceInfo
    );
  }

  private async generateUserTokens(
    userId: string | Types.ObjectId,
    isTwoFactorAuthenticated: boolean,
    deviceInfo: any
  ) {
    const user = await this.findUser(userId.toString(), 'id');

    const payload = {
      userId: user._id,
      isTwoFactorAuthenticated
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '11h',
      secret: process.env.JWT_SECRET
    });

    const refreshToken = uuidv4();

    // Stocker la session
    const sessionId = await this.tokenService.storeUserToken(user._id.toString(), {
      accessToken,
      refreshToken,
      deviceInfo,
      loginTime: new Date(),
    });

    return {
      accessToken,
      refreshToken,
      deviceInfo,
      sessionId
    };
  }
  
  async storeRefreshToken(token: string, userId: string | Types.ObjectId) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      {
        upsert: true,
      },
    );
  }

  async requestReset(email: string) {
    const user = await this.findUser(email, 'email', true);
    // 2. Générer le token
    const token = Math.floor(100000 + Math.random() * 900000).toString();
    const expiryDate = new Date();
    expiryDate.setMinutes(expiryDate.getMinutes() + 15); // Expire dans 15 minutes

    // 3. Sauvegarder le token
    // Supprimer les anciens tokens non utilisés pour cet utilisateur
    await this.ResetTokenModel.deleteMany({
      userId: user._id,
      used: false
    });

    // Créer un nouveau token
    const resetToken = new this.ResetTokenModel({
      userId: user._id,
      token: token,
      expiryDate: expiryDate,
      email: email,
      used: false
    });

    await resetToken.save();

    // 4. Envoyer l'email
    await this.mailService.sendMail({
      to: email,
      subject: 'Réinitialisation de mot de passe',
      text: `Votre code de réinitialisation est: ${token}. Il expirera dans 15 minutes.`,
      html: `
        <p>Votre code de réinitialisation est: <strong>${token}</strong></p>
        <p>Ce code expirera dans 15 minutes.</p>
      `
    });

    return {
      success: true,
      message: 'Code de réinitialisation envoyé par email'
    };
  }

  /**
  * Partie 2FA authentification
  */

  // Trouver un utilisateur par ID
  async findUserById(userId: string): Promise<User | null> {
    return this.findUser(userId, 'id', false);
  }

  // Mettre à jour le secret 2FA d'un utilisateur
  async updateUserTwoFactorSecret(userId: string, secret: string): Promise<User> {
    console.log('Updating 2FA secret for user:', userId, 'Secret:', secret);

    try {
      const updatedUser = await this.UserModel.findByIdAndUpdate(
        userId,
        {
          $set: {
            twoFactorSecret: secret
          }
        },
        {
          new: true,
          runValidators: true
        }
      ).exec();

      if (!updatedUser) {
        throw new NotFoundException(`User with ID ${userId} not found`);
      }
      // Mettre à jour le cache
      await this.redisCacheService.setUser(updatedUser);
      console.log('Updated user:', updatedUser);
      return updatedUser;
    } catch (error) {
      console.error('Error updating 2FA secret:', error);
      throw error;
    }
  }
  
  // Activer la 2FA pour un utilisateur  
  async enableTwoFactorAuth(userId: string): Promise<User> {
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      { isTwoFactorEnabled: true },
      { new: true }
    ).exec();

    if (updatedUser) {
      await this.redisCacheService.setUser(updatedUser);
    }

    return updatedUser;
  }
  
  async disableTwoFactorAuth(userId: string): Promise<User> {
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      {
        isTwoFactorEnabled: false,
        twoFactorSecret: null
      },
      { new: true }
    ).exec();

    if (updatedUser) {
      await this.redisCacheService.setUser(updatedUser);
    }

    return updatedUser;
  }

  async verifyTwoFactorToken(
    userId: string,
    token: string
  ): Promise<LoginResponse> {
    try {
      // Vérifier si l'utilisateur est bloqué
      if (await this.tokenService.isUserBlocked(userId)) {
        throw new UnauthorizedException('Trop de tentatives échouées. Veuillez réessayer plus tard.');
      }

      const user = await this.findUser(userId, 'id', true);

      if (!user.twoFactorSecret) {
        throw new UnauthorizedException('2FA non activé');
      }

      // Récupérer la session temporaire
      const tempSession = await this.tokenService.getTempToken(userId);
      if (!tempSession) {
        throw new UnauthorizedException('Session de vérification 2FA expirée');
      }

      const isValid = this.twoFactorAuthService.validateToken(
        user.twoFactorSecret,
        token
      );

      if (!isValid) {
        const attempts = await this.tokenService.incrementFailedAttempts(userId);
        const remainingAttempts = this.tokenService.MAX_FAILED_ATTEMPTS - attempts;

        throw new UnauthorizedException(
          `Code 2FA invalide. ${remainingAttempts} tentatives restantes.`
        );
      }

      // Réinitialiser le compteur d'échecs
      await this.tokenService.resetFailedAttempts(userId);

      // Générer les nouveaux tokens
      const tokens = await this.generateUserTokens(
        userId,
        true,
        tempSession.deviceInfo
      );

      // Nettoyer la session temporaire
      await this.tokenService.deleteTempToken(userId);

      const loginResponse: LoginResponse = {
        requiresTwoFactor: false,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user,
        tempToken: null,
        sessionId: tokens.sessionId,
        deviceInfo: tempSession.deviceInfo
      };

      return loginResponse;

    } catch (error) {
      this.logger.error(`2FA verification failed for user ${userId}:`, error);
      throw error;
    }
  }

  /**
  * Partie gestion des rôles pour les administrateurs
  */
  async updateUserRole(userId: string, newRole: UserRole, adminId: string) {
    const admin = await this.findUser(adminId, 'id', true);
    if (admin.role !== UserRole.ADMIN) {
      throw new UnauthorizedException('Only administrators can change roles');
    }

    const userToUpdate = await this.findUser(userId, 'id', true);

    if (userToUpdate.role === UserRole.ADMIN) {
      throw new BadRequestException('Cannot change role of an administrator');
    }

    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      { role: newRole },
      { new: true }
    );

    if (updatedUser) {
      await this.redisCacheService.setUser(updatedUser);
    }

    return updatedUser;
  }
  
  async isAdmin(userId: string): Promise<boolean> {
    const user = await this.findUser(userId, 'id', false);
    return user?.role === UserRole.ADMIN;
  }
  
  async getUserPermissions(userId: string) {
    const user = await this.findUser(userId, 'id', true);

    // Récupérer les permissions basées sur le rôle de l'utilisateur
    const permissions = await this.rolesService.getRolePermissions(user.role);

    // Si aucune permission n'est trouvée, retourner au moins la permission d'authentification
    if (!permissions || permissions.length === 0) {
      return [{
        resource: Resource.AUTH,
        actions: [Action.READ]
      }];
    }

    return permissions;
  }

  /**
  * Déconnexion d'une session spécifique
  */
  async logout(userId: string, sessionId: string): Promise<boolean> {
    try {
      // Suppression de la session
      await this.tokenService.deleteSession(userId, sessionId);
      return true;
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  }
  
  /**
  * Déconnexion de toutes les sessions d'un utilisateur
  */
  async logoutAllDevices(userId: string): Promise<boolean> {
    try {
      // Supprimer toutes les sessions de l'utilisateur
      await this.tokenService.deleteAllSessions(userId);
      this.logger.log(`Toutes les sessions ont été déconnectées pour l'utilisateur ${userId}`);

      return true;
    } catch (error) {
      this.logger.error(`Erreur lors de la déconnexion de toutes les sessions:`, error);
      throw error;
    }
  }
  
  /**
  * Révoquer une session spécifique
  */
  async revokeSession(userId: string, sessionId: string): Promise<boolean> {
    try {
      // Vérifier si la session existe
      const session = await this.tokenService.getSession(userId, sessionId);
      if (!session) {
        throw new UnauthorizedException('Session introuvable');
      }

      // Révoquer la session
      await this.tokenService.deleteSession(userId, sessionId);
      this.logger.log(`Session ${sessionId} révoquée pour l'utilisateur ${userId}`);

      return true;
    } catch (error) {
      this.logger.error(`Erreur lors de la révocation de la session:`, error);
      throw error;
    }
  }
  
  /**
  * Récupérer toutes les sessions actives d'un utilisateur
  */
  async getActiveSessions(userId: string): Promise<Session[]> {
    try {
      const sessions = await this.tokenService.getAllSessions(userId);
      return sessions.map(session => ({
        id: session.sessionId || 'unknown',
        deviceInfo: {
          userAgent: session.deviceInfo?.userAgent || 'Unknown',
          ip: session.deviceInfo?.ip || 'Unknown',
          device: session.deviceInfo?.device || 'Unknown'
        },
        createdAt: session.loginTime?.toISOString() || new Date().toISOString(),
        lastActive: session.lastActive?.toISOString() || session.loginTime?.toISOString() || new Date().toISOString()
      }));
    } catch (error) {
      this.logger.error(`Error getting active sessions for user ${userId}:`, error);
      throw error;
    }
  }
}