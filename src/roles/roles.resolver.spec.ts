import { Test, TestingModule } from '@nestjs/testing';
import { RolesResolver } from './roles.resolver';
import { RolesService } from './roles.service';
import { getModelToken } from '@nestjs/mongoose';
import { RoleType } from './schemas/role.schema';


describe('RolesResolver', () => {
  let resolver: RolesResolver;

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
        RolesResolver,
        RolesService,
        {
          provide: getModelToken(RoleType.name),
          useValue: mockRoleTypeModel,
        },
      ],
    }).compile();

    resolver = module.get<RolesResolver>(RolesResolver);
  });

  it('should be defined', () => {
    expect(resolver).toBeDefined();
  });
});