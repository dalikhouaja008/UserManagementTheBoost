// src/authentication/interfaces/tempTokenData.interface.ts
export interface TempTokenData {
  token: string;
  deviceInfo?: any;
  type: 'twoFactor' | 'passwordReset';
  createdAt: Date;
}

// src/authentication/interfaces/tokenData.interface.ts
export interface TokenData {
  accessToken: string;
  refreshToken?: string;
  deviceInfo?: {
    userAgent?: string;
    ip?: string;
    device?: string;
  };
  loginTime: Date;
  lastActive?: Date;
  sessionId?: string;
}