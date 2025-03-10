import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

@Injectable()
export class TwoFactorAuthService {
  // Générer un secret pour l'utilisateur
  generateSecret(): { secret: string; otpauthUrl: string } {
    const secret = speakeasy.generateSecret({ length: 20 });
    return {
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
    };
  }

  // Générer un QR code pour l'utilisateur
  async generateQRCode(otpauthUrl: string): Promise<string> {
    try {
      return await QRCode.toDataURL(otpauthUrl);
    } catch (error) {
      // Propager l'erreur réelle
      throw error instanceof Error ? error : new Error('QR Code generation failed');
    }
  }

  // Valider le code OTP fourni par l'utilisateur
  validateToken(secret: string, token: string): boolean {
    try {
      return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1 // 30 secondes de tolérance
      });
    } catch (error) {
      // Propager l'erreur réelle
      throw error instanceof Error ? error : new Error('Token validation failed');
    }
  }
}