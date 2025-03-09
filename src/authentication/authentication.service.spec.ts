import { Test, TestingModule } from '@nestjs/testing';
import { AuthenticationService } from './authentication.service';
import { MailService } from '../services/mail.service';
import { RolesService } from '../roles/roles.service';
import { JwtService } from '@nestjs/jwt';
import { getModelToken } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { ResetToken } from './schema/resetToken.schema';
import { RefreshToken } from './schema/refreshToken.schema';

describe('AuthenticationService', () => {
  let service: AuthenticationService;

  // Mock pour MailService avec les paramètres utilisés
  const mockMailService = {
    sendMail: jest.fn().mockImplementation(async () => {
      return Promise.resolve();
    }),
    sendPasswordResetEmail: jest.fn().mockImplementation(async () => {
      return Promise.resolve();
    }),
  };

  const mockUserModel = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    findByIdAndUpdate: jest.fn(),
  };

  const mockResetTokenModel = {
    create: jest.fn(),
    findOne: jest.fn(),
    deleteOne: jest.fn(),
  };

  const mockRefreshTokenModel = {
    create: jest.fn(),
    findOne: jest.fn(),
    deleteOne: jest.fn(),
  };

  const mockRolesService = {
    findOne: jest.fn(),
    findById: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthenticationService,
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
        {
          provide: getModelToken(ResetToken.name),
          useValue: mockResetTokenModel,
        },
        {
          provide: getModelToken(RefreshToken.name),
          useValue: mockRefreshTokenModel,
        },
        {
          provide: MailService,
          useValue: mockMailService,
        },
        {
          provide: RolesService,
          useValue: mockRolesService,
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('test-token'),
            verify: jest.fn().mockReturnValue({ userId: 'test-user-id' }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthenticationService>(AuthenticationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('password reset', () => {
    it('should call sendPasswordResetEmail', async () => {
      const email = 'test@example.com';

      mockUserModel.findOne.mockResolvedValueOnce({ email });
      mockResetTokenModel.create.mockResolvedValueOnce({ });

      await service.requestReset(email);

      expect(mockMailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        email,
        expect.any(String)
      );
    });
  });
});