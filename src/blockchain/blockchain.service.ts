import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Contract, JsonRpcProvider, Wallet, InterfaceAbi, ethers } from 'ethers';
import LandRegistryABI from '../blockchain/abis/LandRegistry.json';

@Injectable()
export class BlockchainService implements OnModuleInit {
  private readonly logger = new Logger(BlockchainService.name);
  private provider: JsonRpcProvider;
  private signer: Wallet;
  private landRegistry: Contract;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    await this.initializeBlockchain();
  }

  getProvider(): JsonRpcProvider {
    return this.provider;
  }

  getLandRegistry(): Contract {
    return this.landRegistry;
  }

  private async initializeBlockchain() {
    try {
      this.logger.log('Initializing blockchain connection...');

      const rpcUrl = this.configService.get<string>('SEPOLIA_RPC_URL');
      if (!rpcUrl) {
        throw new Error('SEPOLIA_RPC_URL not configured');
      }

      this.provider = new JsonRpcProvider(rpcUrl);
      await this.provider.ready;
      
      const network = await this.provider.getNetwork();
      this.logger.log(`Connected to network: ${network.name}`);

      const privateKey = this.configService.get<string>('PRIVATE_KEY');
      if (!privateKey) {
        throw new Error('PRIVATE_KEY not configured');
      }

      this.signer = new Wallet(privateKey, this.provider);
      this.logger.log(`Signer address: ${await this.signer.getAddress()}`);

      const registryAddress = this.configService.get<string>('LAND_REGISTRY_ADDRESS');
      if (!registryAddress) {
        throw new Error('LAND_REGISTRY_ADDRESS not configured');
      }

      this.landRegistry = new Contract(
        registryAddress,
        LandRegistryABI.abi as InterfaceAbi,
        this.signer
      );

      await this.verifyContracts();
      this.logger.log('Blockchain service initialized successfully');
    } catch (error) {
      this.logger.error('Error initializing blockchain service:', error);
      throw error;
    }
  }

  private async verifyContracts() {
    try {
      const registryOwner = await this.landRegistry.owner();
      this.logger.log(`LandRegistry connected at: ${this.landRegistry.target}`);
      this.logger.log(`LandRegistry owner: ${registryOwner}`);
    } catch (error) {
      this.logger.error('Contract verification failed:', error);
      throw new Error('Failed to verify contract connections');
    }
  }

  /**
   * Ajoute un validateur dans le contrat LandRegistry
   * @param validatorAddress Adresse Ethereum du validateur
   * @param validatorType Type de validateur (0: Notaire, 1: Géomètre, 2: Expert Juridique)
   * @returns Résultat de la transaction
   */
  async addValidator(validatorAddress: string, validatorType: number): Promise<any> {
    try {
      this.logger.log(`Adding validator ${validatorAddress} of type ${validatorType}`);
      
      // Vérifier que l'adresse est valide
      if (!ethers.isAddress(validatorAddress)) {
        throw new Error(`Invalid Ethereum address: ${validatorAddress}`);
      }
      
      // Vérifier que le type est valide (0, 1 ou 2)
      if (![0, 1, 2].includes(validatorType)) {
        throw new Error(`Invalid validator type: ${validatorType}. Must be 0, 1, or 2.`);
      }
      
      // Vérifier si le validateur existe déjà
      const isAlreadyValidator = await this.landRegistry.validators(validatorAddress);
      if (isAlreadyValidator) {
        throw new Error(`Address ${validatorAddress} is already registered as a validator`);
      }
      
      // Appeler la fonction addValidator du contrat
      const tx = await this.landRegistry.addValidator(validatorAddress, validatorType, {
        gasLimit: BigInt(300000) // Définir une limite de gas appropriée
      });
      
      // Attendre la confirmation
      const receipt = await tx.wait();
      
      // Vérifier le succès de la transaction
      if (receipt.status === 0) {
        throw new Error("Transaction failed");
      }
      
      this.logger.log(`Validator ${validatorAddress} successfully added with type ${validatorType}`, {
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber
      });
      
      return {
        success: true,
        data: {
          validatorAddress,
          validatorType,
          transactionHash: receipt.hash,
          blockNumber: receipt.blockNumber
        },
        message: `Validator ${validatorAddress} successfully added as ${this.getValidatorTypeString(validatorType)}`
      };
    } catch (error) {
      this.logger.error(`Error adding validator ${validatorAddress}:`, error);
      
      // Gérer spécifiquement les erreurs du contrat
      if (error.message.includes("InvalidValidator")) {
        throw new Error(`Invalid validator address: ${validatorAddress}`);
      }
      if (error.message.includes("UnauthorizedAccount")) {
        throw new Error("You don't have permission to add validators");
      }
      
      throw new Error(`Failed to add validator: ${error.message}`);
    }
  }

  /**
   * Convertit le type de validateur en chaîne
   */
  private getValidatorTypeString(type: number): string {
    switch (type) {
      case 0: return 'Notaire';
      case 1: return 'Géomètre';
      case 2: return 'Expert Juridique';
      default: return 'Unknown';
    }
  }
}