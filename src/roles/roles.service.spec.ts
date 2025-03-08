import { Test, TestingModule } from '@nestjs/testing';
import { RolesService } from './roles.service';
import { getModelToken } from '@nestjs/mongoose';
import { UserRole } from './enums/roles.enum';


describe('RolesService', () => {
  let service: RolesService;

  const mockRoleTypeModel = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    findByIdAndUpdate: jest.fn(),
    findByIdAndDelete: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RolesService,
        {
          provide: getModelToken(UserRole.USER),
          useValue: mockRoleTypeModel,
        },
      ],
    }).compile();

    service = module.get<RolesService>(RolesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});