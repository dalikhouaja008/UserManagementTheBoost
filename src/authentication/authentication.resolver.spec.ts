import { Test, TestingModule } from '@nestjs/testing';
import { AuthenticationResolver } from './authentication.resolver';
import { AuthenticationService } from './authentication.service';
import { MailService } from '../services/mail.service'; 

describe('AuthenticationResolver', () => {
  let resolver: AuthenticationResolver;

  const mockAuthService = {
    signup: jest.fn(),
    login: jest.fn(),
    initiatePasswordReset: jest.fn(),
    resetPassword: jest.fn(),
  };

  // Correction du mock MailService en supprimant les paramètres non utilisés
  const mockMailService = {
    sendMail: jest.fn().mockImplementation(async () => {
      return Promise.resolve();
    }),
    sendPasswordResetEmail: jest.fn().mockImplementation(async () => {
      return Promise.resolve();
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthenticationResolver,
        {
          provide: AuthenticationService,
          useValue: mockAuthService,
        },
        {
          provide: MailService,
          useValue: mockMailService,
        },
      ],
    }).compile();

    resolver = module.get<AuthenticationResolver>(AuthenticationResolver);
  });

  it('should be defined', () => {
    expect(resolver).toBeDefined();
  });

  describe('initiatePasswordReset', () => {
    it('should call authService.initiatePasswordReset', async () => {
      const email = 'test@example.com';
      await resolver.requestReset(email);
      expect(mockAuthService.initiatePasswordReset).toHaveBeenCalledWith(email);
    });
  });
});