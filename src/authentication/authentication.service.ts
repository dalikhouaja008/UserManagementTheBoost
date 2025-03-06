import {
  BadRequestException,
  Inject,
  Injectable,
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

@Injectable()
export class AuthenticationService {
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
  ) { }

  async signup(signupData: UserInput) {
    const { email, username, password, publicKey, twoFactorSecret, role, isVerified } = signupData;

    // Vérifier si l'email est déjà utilisé
    const emailInUse = await this.UserModel.findOne({ email });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
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
      isVerified: isVerified || false, // Optionnel, valeur par défaut
    });

    return newUser;
  }

  async login(credentials: LoginInput): Promise<LoginResponse> {
    const { email, password } = credentials;

    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    // Si 2FA est activé
    if (user.isTwoFactorEnabled) {
      // Générer un token temporaire pour la vérification 2FA
      const tempToken = this.jwtService.sign(
        { 
          userId: user._id,
          role: user.role,  
          isTwoFactorAuthenticated: false,
          isTemp: true 
        },
        { expiresIn: '5m' } // Token temporaire valide 5 minutes
      );

      return {
        requiresTwoFactor: true,
        tempToken,
        user,
        accessToken: null,
        refreshToken: null
      };
    }

    // Si pas de 2FA, générer les tokens normaux
    const tokens = await this.generateUserTokens(user._id, true);
    return {
      requiresTwoFactor: false,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user,
      tempToken: null
    };
  }

  async changePassword(userId, oldPassword: string, newPassword: string) {
    //Find the user
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found...');
    }

    //Compare the old password with the password in DB
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Change user's password
    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();
  }

  async forgotPassword(email: string) {
    //Check that user exists
    const user = await this.UserModel.findOne({ email });

    if (user) {
      //If user exists, generate password reset link
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);

      const resetToken = nanoid(64);
      await this.ResetTokenModel.create({
        token: resetToken,
        userId: user._id,
        expiryDate,
        email: email
      });
      //Send the link to the user by email
      this.mailService.sendPasswordResetEmail(email, resetToken);
    }

    return { message: 'If this user exists, they will receive an email' };
  }

  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Refresh Token is invalid');
    }
    return this.generateUserTokens(token.userId.toString(),false);
  }
  async generateUserTokens(userId: string | Types.ObjectId, isTwoFactorAuthenticated = false) {
    const user = await this.UserModel.findById(userId);
    
    const payload = {
      userId: user._id,
      role: user.role,
      isTwoFactorAuthenticated,
    };

    const accessToken = this.jwtService.sign(payload, { 
      expiresIn: '11h',
      secret: process.env.JWT_SECRET 
    });

    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
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
    // 1. Trouver l'utilisateur
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }

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

  async verifyCode(email: string, code: string) {
    const resetToken = await this.ResetTokenModel.findOne({
      email: email,
      token: code,
      used: false,
      expiryDate: { $gt: new Date() }
    });

    if (!resetToken) {
      throw new BadRequestException('Code invalide ou expiré');
    }

    return {
      success: true,
      message: 'Code vérifié avec succès'
    };
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
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }
    // Marquer le token comme utilisé
    resetToken.used = true;
    await resetToken.save();

    return {
      success: true,
      message: 'Mot de passe réinitialisé avec succès',
      user: user
    };
  }

  async validateUser(userId: string): Promise<any> {
    const user = await this.UserModel.findById(userId).exec();
    return user ? user : null;
  }

  //2FA authentication
  // Trouver un utilisateur par ID
  async findUserById(userId: string): Promise<User | null> {
    return this.UserModel.findById(userId).exec();
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
  
      console.log('Updated user:', updatedUser);
      return updatedUser;
    } catch (error) {
      console.error('Error updating 2FA secret:', error);
      throw error;
    }
  }
  // Activer la 2FA pour un utilisateur  
  async enableTwoFactorAuth(userId: string): Promise<User> {
    return this.UserModel.findByIdAndUpdate(
      userId,
      {
        isTwoFactorEnabled: true
      },
      { new: true }
    ).exec();
  }

  async disableTwoFactorAuth(userId: string): Promise<User> {
    return this.UserModel.findByIdAndUpdate(
      userId,
      {
        isTwoFactorEnabled: false,
        twoFactorSecret: null
      },
      { new: true }
    ).exec();
  }

  async verifyTwoFactorToken(userId: string, token: string) {
    const user = await this.UserModel.findById(userId);
    if (!user || !user.twoFactorSecret) {
      throw new UnauthorizedException('Utilisateur non trouvé ou 2FA non activé');
    }

    const isValid = this.twoFactorAuthService.validateToken(
      user.twoFactorSecret, 
      token
    );

    if (!isValid) {
      throw new UnauthorizedException('Code 2FA invalide');
    }

    // Générer un nouveau token avec 2FA validé
    return this.generateUserTokens(userId, true);
  }



//Partie rôle
  async updateUserRole(userId: string, newRole: UserRole, adminId: string) {
    // Vérifier si l'admin a les droits nécessaires
    const admin = await this.UserModel.findById(adminId);
    if (!admin || admin.role !== UserRole.ADMIN) {
      throw new UnauthorizedException('Only administrators can change roles');
    }
  
    // Ne pas permettre de changer le rôle d'un admin
    const userToUpdate = await this.UserModel.findById(userId);
    if (!userToUpdate) {
      throw new NotFoundException('User not found');
    }
    if (userToUpdate.role === UserRole.ADMIN) {
      throw new BadRequestException('Cannot change role of an administrator');
    }
  
    // Mettre à jour le rôle
    const updatedUser = await this.UserModel.findByIdAndUpdate(
      userId,
      { role: newRole },
      { new: true }
    );
  
    return updatedUser;
  }
  async isAdmin(userId: string): Promise<boolean> {
    const user = await this.UserModel.findById(userId);
    return user?.role === UserRole.ADMIN;
  }
  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
  
    // Récupérer les permissions basées sur le rôle de l'utilisateur
    const permissions = await this.rolesService.getRolePermissions(user.role);
  
    // Si aucune permission n'est trouvée, retourner au moins la permission d'authentification
    if (!permissions || permissions.length === 0) {
      return [{
        resource: Resource.AUTH,
        actions: [Action.read]
      }];
    }
  
    return permissions;
  }

}