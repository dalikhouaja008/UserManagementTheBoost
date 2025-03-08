interface TokenData {
    accessToken: string;
    refreshToken?: string;
    deviceInfo?: {
      userAgent?: string;
      ip?: string;
      device?: string;
    };
    loginTime: Date;
    lastActive: Date;
  }