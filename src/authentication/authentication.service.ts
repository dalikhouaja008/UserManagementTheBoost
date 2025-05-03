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
import { UserRole, isValidatorRole } from 'src/roles/enums/roles.enum';
import { Resource } from 'src/roles/enums/resource.enum';
import { Action } from 'src/roles/enums/action.enum';
import { RedisCacheService } from 'src/redis/redis-cahce.service';
import { TokenService } from './token.service';
import { Session } from './dto/session.type';
import { TwilioService } from 'src/services/twilio.service';
import { VerificationToken } from './schema/verificationToken.schema';
import { BlockchainService } from 'src/blockchain/blockchain.service';

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
    @InjectModel(VerificationToken.name)
    private VerificationTokenModel: Model<VerificationToken>,
    private jwtService: JwtService,
    private mailService: MailService,
    @Inject(forwardRef(() => RolesService))
    private twilioService: TwilioService,
    private rolesService: RolesService,
    private twoFactorAuthService: TwoFactorAuthService,
    private readonly redisCacheService: RedisCacheService,
    private readonly tokenService: TokenService,
    private readonly blockchainService: BlockchainService
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
 * avec support pour l'enregistrement des validateurs blockchain
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

    // Créer l'utilisateur avec les champs fournis
    const newUser = await this.UserModel.create({
      username,
      email,
      password: hashedPassword,

      publicKey: publicKey || null, // Optionnel
      twoFactorSecret: twoFactorSecret || null, // Optionnel
      role: role || UserRole.USER, // Utilisez 'user' comme valeur par défaut si role n'est pas fourni
      isVerified: isVerified || false,
      phoneNumber: phoneNumber || null, // Optionnel, valeur par défaut

    });

    // Mettre le nouvel utilisateur en cache
    await this.redisCacheService.setUser(newUser);

    return newUser;
  }
  /**
    * Send verification email to a newly registered user
    */
  async sendVerificationEmail(user: User): Promise<void> {
    // Generate a verification token
    const token = nanoid(64);
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 24); // 24 hours expiry

    // Save the verification token
    await this.VerificationTokenModel.create({
      userId: user._id,
      token,
      expiryDate,
      email: user.email,
      used: false
    });

    // Send the verification email
    await this.mailService.sendVerificationEmail(user.email, token);
    this.logger.log(`Verification email sent to ${user.email}`);
  }

  /**
  * Verify user email with token
  */
  async verifyEmail(token: string): Promise<User> {
    // Find the verification token
    const verificationToken = await this.VerificationTokenModel.findOne({
      token,
      used: false,
      expiryDate: { $gt: new Date() }
    });

    if (!verificationToken) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Update the user as verified
    const user = await this.UserModel.findByIdAndUpdate(
      verificationToken.userId,
      { isVerified: true },
      { new: true }
    );

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Mark token as used
    verificationToken.used = true;
    await verificationToken.save();

    // Update user in cache
    await this.redisCacheService.setUser(user);

    // Send welcome email
    try {
      await this.mailService.sendWelcomeEmail(user.email, user.username);
    } catch (error) {
      this.logger.error(`Failed to send welcome email: ${error.message}`);
      // Continue execution even if welcome email fails
    }

    return user;
  }

  /**
  * Send notification when account details are changed
  */
  async notifyAccountChange(userId: string, changeType: string, details?: string): Promise<void> {
    try {
      const user = await this.findUser(userId, 'id');
      if (!user) {
        this.logger.warn(`Cannot send account change notification - user ${userId} not found`);
        return;
      }

      // Send the notification email
      await this.mailService.sendAccountChangeEmail(user.email, {
        changeType,
        timestamp: new Date(),
        details
      });

      this.logger.log(`Account change notification sent to ${user.email}: ${changeType}`);
    } catch (error) {
      this.logger.error(`Failed to send account change notification: ${error.message}`);
      // Don't throw - this is a notification that shouldn't block the operation
    }
  }

  /**
  * Update account profile with notification
  */
  async updateUserProfile(userId: string, updateData: any): Promise<User> {
    // Check what fields are being updated to determine change type
    const changeTypes = [];
    if (updateData.email) changeTypes.push('Email');
    if (updateData.phoneNumber) changeTypes.push('Phone Number');
    if (updateData.username) changeTypes.push('Username');

    const changeType = changeTypes.length > 0
      ? `Profile Update: ${changeTypes.join(', ')}`
      : 'Profile Update';

    // Update the user
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true }
    );

    if (!updatedUser) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    // Invalidate cache
    if (updateData.email) {
      await this.redisCacheService.invalidateUser(userId, updateData.email);
    }

    // Update cache with new data
    await this.redisCacheService.setUser(updatedUser);

    // Send notification
    await this.notifyAccountChange(userId, changeType);

    return updatedUser;
  }

  /**
  * Check if login is from a new device and send security notification if needed
  */
  async checkNewDeviceAndNotify(user: User, deviceInfo: any): Promise<void> {
    try {
      // Get user's previous sessions
      const sessions = await this.tokenService.getAllSessions(user._id.toString());

      // Check if this is a new device
      const isNewDevice = !sessions.some(session =>
        session.deviceInfo?.device === deviceInfo.device &&
        session.deviceInfo?.ip === deviceInfo.ip
      );

      // If new device, send notification
      if (isNewDevice && sessions.length > 0) {
        this.logger.log(`New device login detected for user ${user.email}`);

        // Get geolocation data (simplified example)
        const location = await this.getLocationFromIP(deviceInfo.ip);

        // Send security alert
        await this.mailService.sendSecurityAlert(user.email, {
          alertType: 'New Device Login',
          timestamp: new Date(),
          device: deviceInfo.device || deviceInfo.userAgent || 'Unknown device',
          location: location || 'Unknown location',
          ipAddress: deviceInfo.ip || 'Unknown IP',
        });
      }
    } catch (error) {
      // Log but don't throw - this shouldn't prevent login
      this.logger.error(`Error checking for new device: ${error.message}`);
    }
  }

  /**
  * Mock function to get location from IP (in a real app, use a geolocation service)
  */
  private async getLocationFromIP(ip: string): Promise<string> {
    // In a real implementation, use a geolocation service API
    // This is just a placeholder
    return 'Unknown location';
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

      // Check if login is from a new device and send security alert if needed
      await this.checkNewDeviceAndNotify(user, deviceInfo);

      // Utilisation de la fonction utilitaire
      const isValidator = isValidatorRole(user.role);

      if (user.isTwoFactorEnabled && !isValidator) {
        console.log(`[${timestamp}] 🔐 2FA required for regular user: ${user.email}`);

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

      console.log(`[${timestamp}] 🔓 Direct access granted for ${isValidator ? 'validator' : 'user'}: ${user.email}`);

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
  /*async login(credentials: LoginInput, deviceInfo: any): Promise<LoginResponse> {
    const timestamp = new Date().toISOString();

    try {
      console.log(`🔑 Login attempt for email: ${credentials.email}`);

      // 1. Vérifier l'utilisateur
      const user = await this.findUser(credentials.email, 'email');
      if (!user) {
        this.logger.warn(` ❌ User not found: ${credentials.email}`);
        throw new UnauthorizedException('Identifiants invalides');
      }

      // 2. Vérifier le mot de passe
      const isPasswordValid = await bcrypt.compare(
        credentials.password,
        user.password
      );


      if (!isPasswordValid) {
        this.logger.warn(` ❌ Invalid password for user: ${credentials.email}`);
        throw new UnauthorizedException('Identifiants invalides');
      }

      // 3. Récupérer et vérifier le rôle
      let userRole;
      try {
        userRole = await this.rolesService.findByName(user.role);
        this.logger.debug(`Found role ${user.role} with permissions:`, userRole.permissions);
      } catch (error) {
        this.logger.error(`❌ Role not found for user: ${credentials.email}, role: ${user.role}`);
        throw new UnauthorizedException('Configuration de rôle invalide');
      }


      // 3. Si 2FA est activé, gérer temporairement
      if (user.isTwoFactorEnabled) {
        this.logger.log(` 🔐 2FA required for user: ${credentials.email}`);

        const tempToken = this.jwtService.sign(
          { userId: user._id, isTemp: true },
          { expiresIn: '5m', secret: process.env.JWT_SECRET }
        );

        await this.tokenService.storeTempToken(user._id.toString(), {
          token: tempToken,
          deviceInfo,
          type: 'twoFactor',
        });

        return {
          requiresTwoFactor: true,
          tempToken,
          accessToken: null,
          refreshToken: null,
          user,
          deviceInfo,
          sessionId: null
        };
      }

      // 4. Générer les tokens avec les permissions et stocker la session
      this.logger.log(`🎟️ Generating tokens for user: ${credentials.email}`);
      const tokens = await this.generateUserTokens(
        user._id,
        false,
        deviceInfo
      );

      this.logger.log(`✅ Login successful: ${credentials.email}`);

      // 5. Retourner la réponse de login
      return {
        requiresTwoFactor: false,
        tempToken: null,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          ...user.toObject(),
          permissions: tokens.permissions
        },
        deviceInfo,
        sessionId: tokens.sessionId
      };

    } catch (error) {
      this.logger.error(`[${timestamp}] ❌ Login failed: ${error.message}`);
      throw error;
    }
  }*/
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

    // Invalidate cache
    await this.redisCacheService.invalidateUser(userId, user.email);

    // Mettre à jour le cache avec le nouvel utilisateur
    if (updatedUser) {
      await this.redisCacheService.setUser(updatedUser);
    }

    // Send password change notification
    await this.notifyAccountChange(userId, 'Password Changed');

    // Send security alert for password change
    await this.mailService.sendSecurityAlert(user.email, {
      alertType: 'Password Changed',
      timestamp: new Date(),
      device: 'N/A',
      location: 'N/A',
      ipAddress: 'N/A'
    });

    return updatedUser;
  }

  async forgotPassword(identifier: string): Promise<void> {
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
    let user;
    if (isEmail) {
      user = await this.UserModel.findOne({ email: identifier });
    } else {
      let normalizedPhone = identifier.startsWith('+216') ? identifier : `+216${identifier}`;
      user = await this.UserModel.findOne({ phoneNumber: normalizedPhone });
    }

    if (!user) {
      this.logger.warn(`User with ${isEmail ? 'email' : 'phone number'} ${identifier} not found`);
      throw new Error('User not found');  // ✅ Throw error here
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
      phoneNumber: identifier,
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


  async resetPasswordWithToken(token: string, newPassword: string): Promise<User> {
    const resetToken = await this.ResetTokenModel.findOne({ token });

    if (!resetToken || resetToken.expiryDate < new Date()) {
      throw new BadRequestException('Invalid or expired token');
    }

    const user = await this.UserModel.findById(resetToken.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    resetToken.used = true;
    await resetToken.save();

    return user;
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
    const sessionId = uuidv4();
    const user = await this.findUser(userId.toString(), 'id');

    // Récupérer les permissions du rôle
    const userRole = await this.rolesService.findByName(user.role);
    const permissions = userRole?.permissions || [];

    const payload = {
      userId: user._id,
      email: user.email,
      ethAddress: user.publicKey,
      role: user.role,
      permissions: await this.rolesService.getRolePermissions(user.role),
      sessionId,
      isTwoFactorAuthenticated
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '11h',
      secret: process.env.JWT_SECRET
    });

    const refreshToken = uuidv4();

    // Stocker la session
    const tokenData: Omit<TokenData, 'lastActive'> = {
      accessToken,
      refreshToken,
      deviceInfo,
      loginTime: new Date(),
      permissions
    };

    await this.tokenService.storeUserToken(user._id.toString(), tokenData);

    return {
      accessToken,
      refreshToken,
      deviceInfo,
      sessionId,
      permissions
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

  async verifyCode(identifier: string, code: string) {
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
      throw new BadRequestException('Invalid or expired OTP code.');
    }

    resetToken.used = true;
    await resetToken.save();

    return 'Code verified successfully!';
  }


  async forgotPasswordSms(phoneNumber: string): Promise<void> {
    const user = await this.UserModel.findOne({ phoneNumber });

    if (user) {
      const otp = generateOtp();
      const expiryDate = new Date();
      expiryDate.setMinutes(expiryDate.getMinutes() + 15); // OTP valid for 10 mins

      await this.ResetTokenModel.create({
        token: otp,
        userId: user._id,
        expiryDate,
        email: user.email,
        phoneNumber: phoneNumber,
      });

      await this.twilioService.sendSms(phoneNumber, `Your OTP code is: ${otp}`);
    } else {
      this.logger.warn(`User with phone number ${phoneNumber} not found`);
    }
  }

  async resetPassword(email: string, code: string, newPassword: string) {
    const resetToken = await this.ResetTokenModel.findOne({
      email: email,
      token: code,
      used: false,
      expiryDate: { $gt: new Date() }
    });

    if (!resetToken) {
      throw new BadRequestException('Code invalide ou expiré');
    }

    // Hasher le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Mettre à jour le mot de passe
    await this.UserModel.findByIdAndUpdate(resetToken.userId, {
      password: hashedPassword
    });
    //chercher user
    const user = await this.findUser(email, 'email', true);

    // Invalider le cache après changement de mot de passe
    await this.redisCacheService.invalidateUser(user._id.toString(), email);
    // Marquer le token comme utilisé
    resetToken.used = true;
    await resetToken.save();

    return {
      success: true,
      message: 'Mot de passe réinitialisé avec succès',
      user: user
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


  // Dans le TokenService, ajoutez cette méthode si elle n'existe pas :
  async getTempToken(userId: string) {
    try {
      const tempToken = await this.redisCacheService.get(`temp_token:${userId}`);
      return tempToken;
    } catch (error) {
      this.logger.error(`Error getting temp token for user ${userId}:`, error);
      return null;
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
      this.logger.debug(`Getting active sessions for user ${userId}`);
      const sessions = await this.tokenService.getAllSessions(userId);

      this.logger.debug('Raw sessions:', JSON.stringify(sessions, null, 2));

      const mappedSessions = sessions.map(session => {
        const mappedSession = {
          id: session.id || session.sessionId || session._id || uuidv4(),
          deviceInfo: {
            userAgent: session.deviceInfo?.userAgent || 'Unknown',
            ip: session.deviceInfo?.ip || 'Unknown',
            device: session.deviceInfo?.device || 'Unknown'
          },
          createdAt: session.loginTime || new Date().toISOString(),
          lastActive: session.lastActive || session.loginTime || new Date().toISOString()
        };

        this.logger.debug('Mapped session:', JSON.stringify(mappedSession, null, 2));
        return mappedSession;
      });

      return mappedSessions;
    } catch (error) {
      this.logger.error(`Error getting active sessions for user ${userId}:`, error);
      throw error;
    }
  }
  async saveMetamaskPublicKey(
    userId: string,
    ethereumAddress: string,
    publicKey: string
  ): Promise<User> {
    const user = await this.findUser(userId, 'id', true);

    // Update the user with both the Ethereum address and the public key
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      {
        publicKey: publicKey,
        ethereumAddress: ethereumAddress // You might want to add this field to your User schema
      },
      { new: true }
    );

    if (!updatedUser) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    // Invalidate the cache and update it
    await this.redisCacheService.invalidateUser(userId, user.email);
    await this.redisCacheService.setUser(updatedUser);

    return updatedUser;
  }



}