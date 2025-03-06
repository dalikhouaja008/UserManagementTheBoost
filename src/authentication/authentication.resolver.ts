import { BadRequestException,  UnauthorizedException, UseGuards } from '@nestjs/common';
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
import { Permissions } from '../decorators/permissions.decorator';

@Resolver(() => User)
export class AuthenticationResolver {
  constructor(
    private readonly authService: AuthenticationService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly jwtService: JwtService,
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
  async login(@Args('credentials') credentials: LoginInput) {
    if (!credentials.email || !credentials.password) {
      throw new BadRequestException('Données manquantes');
    }
    return this.authService.login(credentials);
  }
  // Mutation pour rafraîchir les tokens
  @Mutation(() => String)
  @UseGuards(AuthenticationGuard)
  async refreshTokens(@Args('refreshTokenData') refreshTokenData: RefreshTokenInput) {
    return this.authService.refreshTokens(refreshTokenData.refreshToken);
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
  const currentUser = 'raednas';

  try {
    console.log(`[${timestamp}] AuthResolver: 🔐 Verifying 2FA login`,
                '\n└─ User:', currentUser,
                '\n└─ Token length:', token.length);

    // Extraire le token des headers
    const authHeader = context.req.headers.authorization;
    if (!authHeader) {
      console.error(`[${timestamp}] AuthResolver: ❌ No authorization header`,
                   '\n└─ User:', currentUser);
      throw new UnauthorizedException('Token manquant');
    }

    const tempToken = authHeader.replace('Bearer ', '');

    // Décoder le token temporaire
    let decodedToken;
    try {
      decodedToken = this.jwtService.verify(tempToken);
      console.log(`[${timestamp}] AuthResolver: ✅ Temp token decoded`,
                 '\n└─ User:', currentUser,
                 '\n└─ UserId:', decodedToken.userId,
                 '\n└─ IsTemp:', decodedToken.isTemp);
    } catch (error) {
      console.error(`[${timestamp}] AuthResolver: ❌ Invalid token`,
                   '\n└─ User:', currentUser,
                   '\n└─ Error:', error.message);
      throw new UnauthorizedException('Token invalide');
    }

    // Vérifier que c'est un token temporaire
    if (!decodedToken.isTemp) {
      console.error(`[${timestamp}] AuthResolver: ❌ Not a temporary token`,
                   '\n└─ User:', currentUser);
      throw new UnauthorizedException('Token non valide pour la vérification 2FA');
    }

    // Trouver l'utilisateur avec l'ID du token
    const user = await this.authService.findUserById(decodedToken.userId);
    if (!user) {
      console.error(`[${timestamp}] AuthResolver: ❌ User not found`,
                   '\n└─ User:', currentUser,
                   '\n└─ UserId:', decodedToken.userId);
      throw new UnauthorizedException('Utilisateur non trouvé');
    }

    console.log(`[${timestamp}] AuthResolver: 👤 User found`,
                '\n└─ User:', currentUser,
                '\n└─ Email:', user.email,
                '\n└─ Has 2FA:', user.isTwoFactorEnabled);

    // Vérifier que 2FA est activé
    if (!user.isTwoFactorEnabled) {
      console.error(`[${timestamp}] AuthResolver: ❌ 2FA not enabled`,
                   '\n└─ User:', currentUser,
                   '\n└─ Email:', user.email);
      throw new UnauthorizedException('2FA non activé pour cet utilisateur');
    }

    // Valider le code OTP
    const isValid = this.twoFactorAuthService.validateToken(
      user.twoFactorSecret, 
      token
    );

    if (!isValid) {
      console.error(`[${timestamp}] AuthResolver: ❌ Invalid OTP`,
                   '\n└─ User:', currentUser,
                   '\n└─ Email:', user.email);
      throw new UnauthorizedException('Code OTP invalide');
    }

    console.log(`[${timestamp}] AuthResolver: ✅ OTP verified`,
                '\n└─ User:', currentUser,
                '\n└─ Email:', user.email);

    // Générer les tokens JWT
    const tokens = await this.authService.generateUserTokens(user._id);

    console.log(`[${timestamp}] AuthResolver: 🎟️ Tokens generated`,
                '\n└─ User:', currentUser,
                '\n└─ Email:', user.email);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: user,
      requiresTwoFactor: false,
      tempToken: null
    };

  } catch (error) {
    console.error(`[${timestamp}] AuthResolver: ❌ Verification failed`,
                 '\n└─ User:', currentUser,
                 '\n└─ Error:', error.message);
    throw error;
  }
}
}
