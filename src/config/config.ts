// src/config/config.ts
export default () => ({
  database: {
    connectionString: process.env.MONGO_URL || 'mongodb://localhost:27017/the-boost',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'defaultDevSecretKey',
    expiration: process.env.JWT_EXPIRATION || '10h',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  },
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10) || 587,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    from: process.env.EMAIL_FROM || 'Auth-backend service <noreply@example.com>',
  },
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID,
    authToken: process.env.TWILIO_AUTH_TOKEN,
    phoneNumber: process.env.TWILIO_PHONE_NUMBER,
  },
  frontend: {
    url: process.env.FRONTEND_URL || 'http://localhost:3000',
  },
  server: {
    httpPort: parseInt(process.env.HTTP_PORT, 10) || 3000,
    tcpPort: parseInt(process.env.TCP_PORT, 10) || 3002,
  },
});