

interface TempTokenData {
    token: string;
    deviceInfo?: any;
    type: 'twoFactor' | 'passwordReset';
    createdAt: Date;
  }