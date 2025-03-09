import { Resolver } from '@nestjs/graphql';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthenticationService } from './authentication.service';
import { PATTERNS } from '../constants/service';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthenticationGuard } from '../guards/authentication.guard';
import { MicroserviceAuthGuard } from '../guards/microservice-auth.guard';

@Resolver()
@UseGuards(AuthenticationGuard) // Guard global pour le resolver
export class AuthenticationMicroserviceResolver {
  constructor(
    private readonly authService: AuthenticationService,
    private readonly jwtService: JwtService
  ) {}

  @UseGuards(MicroserviceAuthGuard) // Guard spécifique pour cette méthode
  @MessagePattern(PATTERNS.LOGIN)
  async authenticate(@Payload() data: any) {
    try {
      // Vérifier et décoder le token JWT
      const decoded = await this.jwtService.verifyAsync(data.Authentication, {
        secret: process.env.JWT_SECRET
      });

      // Valider l'utilisateur avec l'ID extrait du token
      const user = await this.authService.validateUser(decoded.userId);
      
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Vérifier si l'utilisateur nécessite une 2FA
      if (user.isTwoFactorEnabled && !decoded.isTwoFactorAuthenticated) {
        return {
          success: false,
          requiresTwoFactor: true,
          error: 'Two-factor authentication required'
        };
      }

      return {
        success: true,
        data: {
          userId: user._id,
          email: user.email,
          username: user.username,
          role: user.role,
          isTwoFactorEnabled: user.isTwoFactorEnabled,
          isTwoFactorAuthenticated: decoded.isTwoFactorAuthenticated
        }
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
        requiresTwoFactor: false
      };
    }
  }

  @UseGuards(AuthenticationGuard)
  @MessagePattern(PATTERNS.VERIFY_2FA)
  async verify2FA(@Payload() data: any) {
    try {
      const { userId, token } = data;
      const result = await this.authService.verifyTwoFactorToken(userId, token);
      return {
        success: true,
        data: result
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}