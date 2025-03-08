import { BadRequestException, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { LoginInput } from './dto/login.input';
import { RefreshTokenInput } from './dto/refreshToken.input';
import { ChangePasswordInput } from './dto/changePassword.input';
import { ForgotPasswordInput } from './dto/forgetPassword.input';
import { ResetPasswordInput } from './dto/resetPassword.input';
import { AuthenticationService } from './authentication.service';
import { UserInput } from './dto/signup.input';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { User } from './schema/user.schema';
import { LoginResponse } from './responses/login.response';
import { TwoFactorAuthService } from './TwoFactorAuth.service';
import { JwtService } from '@nestjs/jwt';
import { AuthorizationGuard } from 'src/guards/authorization.guards';
import { Resource } from 'src/roles/enums/resource.enum';
import { Action } from 'src/roles/enums/action.enum';
import { Permissions } from '../core/decorators/permissions.decorator';
import { DeviceInfo } from 'src/core/decorators/device-info.decorator';
import { TokenService } from './token.service';
import { Session } from './dto/session.type';

@Resolver(() => User)
export class AuthenticationResolver {
  constructor(
    private readonly authService: AuthenticationService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly jwtService: JwtService,
    private readonly tokenService: TokenService
  ) { }


  @Mutation(() => User)
  async signUp(@Args('signupData') signupData: UserInput) {
    return this.authService.signup(signupData);
  }

  // Création de compte spécial (NOTAIRE, GEOMETRE, EXPERT_JURIDIQUE) - Réservé à l'admin
  @Mutation(() => User)
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions({
    resource: Resource.USERS,
    actions: [Action.CREATE]
  })
  async createSpecialUser(@Args('input') userInput: UserInput) {
    // Vérifie que le rôle est valide pour les comptes spéciaux
    if (!['NOTAIRE', 'GEOMETRE', 'EXPERT_JURIDIQUE'].includes(userInput.role)) {
      throw new Error('Invalid role for special user creation');
    }
    return this.authService.signup(userInput);
  }
  @Mutation(() => LoginResponse)
  async login(
    @Args('credentials') credentials: LoginInput,
    @Context() context,
    @DeviceInfo() deviceInfo: any
  ) {
    const timestamp = '2025-03-08 15:14:45';
    console.log(`[${timestamp}] AuthResolver: 🔑 Login attempt`);

    if (!credentials.email || !credentials.password) {
      console.error(`[${timestamp}] AuthResolver: ❌ Missing credentials`);
      throw new BadRequestException('Données manquantes');
    }

    // Extraire les informations de base
    const deviceData = {
      userAgent: context.req.headers['user-agent'],
      ip: context.req.ip,
      ...deviceInfo
    };

    console.log(`[${timestamp}] AuthResolver: 📱 Device info detected`,
      '\n└─ IP:', deviceData.ip,
      '\n└─ Device:', deviceData.device,
      '\n└─ Browser:', deviceData.browser);

    // Appeler le service avec les deux paramètres requis
    return this.authService.login(credentials, deviceData);
  }
  // Mutation pour changer le mot de passe
  @UseGuards(AuthenticationGuard) // Protéger cette mutation avec un guard d'authentification
  @Mutation(() => String)
  @UseGuards(AuthenticationGuard)
  async changePassword(@Args('changePasswordData') changePasswordData: ChangePasswordInput) {
    return this.authService.changePassword(
      changePasswordData.userId,
      changePasswordData.oldPassword,
      changePasswordData.newPassword,
    );
  }

  // Mutation pour demander une réinitialisation de mot de passe
  @Mutation(() => String)
  async forgotPassword(@Args('forgotPasswordData') forgotPasswordData: ForgotPasswordInput) {
    return this.authService.forgotPassword(forgotPasswordData.email);
  }

  // Mutation pour demander un code de réinitialisation
  @Mutation(() => String)
  async requestReset(@Args('email') email: string) {
    return this.authService.requestReset(email);
  }

  // Mutation pour vérifier un code de réinitialisation
  @Mutation(() => String)
  async verifyCode(@Args('email') email: string, @Args('code') code: string) {
    return this.authService.verifyCode(email, code);
  }

  // Mutation pour réinitialiser le mot de passe
  @Mutation(() => User)
  async resetPassword(@Args('resetPasswordData') resetPasswordData: ResetPasswordInput) {
    return this.authService.resetPassword(
      resetPasswordData.email,
      resetPasswordData.code,
      resetPasswordData.newPassword,
    );
  }

  // Query pour valider un utilisateur 
  @Query(() => User)
  async validateUser(@Args('userId') userId: string) {
    return this.authService.validateUser(userId);
  }

  //Partie 2FA
  // Mutation pour activer la 2FA
  @UseGuards(AuthenticationGuard)
  @Mutation(() => String)
  async enableTwoFactorAuth(@Context() context) {
    const req = context.req;
    const user = req.user;

    console.log('User from context:', user); // Voyons la structure exacte

    if (!user) {
      throw new UnauthorizedException('Utilisateur non authentifié');
    }

    // L'ID peut être dans différentes propriétés selon votre implementation de AuthGuard
    const userId = user.id || user._id || user.userId;
    console.log('UserId extracted:', userId);

    if (!userId) {
      throw new UnauthorizedException('ID utilisateur non trouvé');
    }

    // Générer un secret 2FA
    const secret = this.twoFactorAuthService.generateSecret();

    try {
      // Mettre à jour l'utilisateur avec le secret 2FA
      const updatedUser = await this.authService.updateUserTwoFactorSecret(userId, secret.secret);
      console.log('Updated user:', updatedUser);

      // Générer un QR code pour l'utilisateur
      const qrCodeUrl = await this.twoFactorAuthService.generateQRCode(secret.otpauthUrl);
      return qrCodeUrl;
    } catch (error) {
      throw new Error(`Erreur lors de l'activation de la 2FA: ${error.message}`);
    }
  }

  // Mutation pour valider le code OTP 
  //activation initiale de la 2FA 
  @UseGuards(AuthenticationGuard)
  @Mutation(() => Boolean)
  async verifyTwoFactorAuth(
    @Context() context: any,
    @Args('token') token: string,
  ): Promise<boolean> {
    const req = context.req;
    const userId = req.user.userId;

    const user = await this.authService.findUserById(userId);

    if (!user) {
      throw new UnauthorizedException('Utilisateur non authentifié');
    }
    //console.log(user);

    if (!user.twoFactorSecret) {
      throw new Error('2FA non activée pour cet utilisateur');
    }

    // Valider le code OTP
    const isValid = this.twoFactorAuthService.validateToken(user.twoFactorSecret, token);

    if (isValid) {
      // Activer la 2FA pour l'utilisateur
      await this.authService.enableTwoFactorAuth(userId);
    }

    return isValid;
  }


  // Mutation pour valider le code OTP après la connexion
  //@UseGuards(AuthenticationGuard)
  @Mutation(() => LoginResponse)
  async verifyTwoFactorLogin(
    @Context() context: any,
    @Args('token') token: string,
  ) {
    const timestamp = '2025-02-17 11:29:37';

    try {
      console.log(`[${timestamp}] AuthResolver: 🔐 Verifying 2FA login`,
        '\n└─ Token length:', token.length);

      // Extraire le token des headers
      const authHeader = context.req.headers.authorization;
      if (!authHeader) {
        console.error(`[${timestamp}] AuthResolver: ❌ No authorization header`);
        throw new UnauthorizedException('Token manquant');
      }

      const tempToken = authHeader.replace('Bearer ', '');

      // Décoder le token temporaire
      let decodedToken;
      try {
        decodedToken = this.jwtService.verify(tempToken);
        console.log(`[${timestamp}] AuthResolver: ✅ Temp token decoded`,
          '\n└─ UserId:', decodedToken.userId,
          '\n└─ IsTemp:', decodedToken.isTemp);
      } catch (error) {
        console.error(`[${timestamp}] AuthResolver: ❌ Invalid token`,
          '\n└─ Error:', error.message);
        throw new UnauthorizedException('Token invalide');
      }

      // Vérifier que c'est un token temporaire
      if (!decodedToken.isTemp) {
        console.error(`[${timestamp}] AuthResolver: ❌ Not a temporary token`);
        throw new UnauthorizedException('Token non valide pour la vérification 2FA');
      }

      // Trouver l'utilisateur avec l'ID du token
      const user = await this.authService.findUserById(decodedToken.userId);
      if (!user) {
        console.error(`[${timestamp}] AuthResolver: ❌ User not found`,
          '\n└─ UserId:', decodedToken.userId);
        throw new UnauthorizedException('Utilisateur non trouvé');
      }

      console.log(`[${timestamp}] AuthResolver: 👤 User found`,
        '\n└─ Email:', user.email,
        '\n└─ Has 2FA:', user.isTwoFactorEnabled);

      // Vérifier que 2FA est activé
      if (!user.isTwoFactorEnabled) {
        console.error(`[${timestamp}] AuthResolver: ❌ 2FA not enabled`,
          '\n└─ Email:', user.email);
        throw new UnauthorizedException('2FA non activé pour cet utilisateur');
      }

      // Récupérer la session temporaire avec les infos du device
      const tempSession = await this.tokenService.getTempToken(decodedToken.userId);
      if (!tempSession) {
        console.error(`[${timestamp}] AuthResolver: ❌ Temp session not found`);
        throw new UnauthorizedException('Session temporaire expirée');
      }

      // Valider le code OTP
      const isValid = this.twoFactorAuthService.validateToken(
        user.twoFactorSecret,
        token
      );

      if (!isValid) {
        console.error(`[${timestamp}] AuthResolver: ❌ Invalid OTP`,
          '\n└─ Email:', user.email);
        throw new UnauthorizedException('Code OTP invalide');
      }

      console.log(`[${timestamp}] AuthResolver: ✅ OTP verified`,
        '\n└─ Email:', user.email);

      // Générer les tokens JWT avec les infos du device de la session temporaire
      const tokens = await this.authService.verifyTwoFactorToken(
        decodedToken.userId,
        token
      );

      console.log(`[${timestamp}] AuthResolver: 🎟️ Tokens generated`,
        '\n└─ Email:', user.email);

      // Supprimer la session temporaire
      await this.tokenService.deleteTempToken(decodedToken.userId);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: tokens.user,
        requiresTwoFactor: false,
        tempToken: null,
        deviceInfo: tokens.deviceInfo,
        sessionId: tokens.sessionId
      };

    } catch (error) {
      console.error(`[${timestamp}] AuthResolver: ❌ Verification failed`,
        '\n└─ Error:', error.message);
      throw error;
    }
  }

  //Sessions
  @Query(() => [Session])
  @UseGuards(AuthenticationGuard)
  async getActiveSessions(@Context() context) {
    const userId = context.req.user.userId;
    return this.authService.getActiveSessions(userId);
  }

  @Mutation(() => Boolean)  // Assurez-vous que c'est bien Boolean
  @UseGuards(AuthenticationGuard)
  async logout(@Context() context): Promise<boolean> {  // Retourne explicitement un boolean
    try {
      const userId = context.req.user.userId;
      const sessionId = context.req.sessionId;

      await this.authService.logout(userId, sessionId);
      return true;  // Retourne une valeur boolean explicite
    } catch (error) {
      console.error('Logout error:', error);
      return false;
    }
  }


  @Mutation(() => Boolean)
  @UseGuards(AuthenticationGuard)
  async logoutAllDevices(@Context() context) {
    const userId = context.req.user.userId;
    return this.authService.logoutAllDevices(userId);
  }

  @Mutation(() => Boolean)
  @UseGuards(AuthenticationGuard)
  async revokeSession(
    @Context() context,
    @Args('sessionId') sessionId: string
  ) {
    const userId = context.req.user.userId;
    return this.authService.revokeSession(userId, sessionId);
  }
}
