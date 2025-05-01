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

  constructor(private configService: ConfigService) { }

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

      // Vérifier que l'adresse est valide et standardisée
      if (!ethers.isAddress(validatorAddress)) {
        throw new Error(`Invalid Ethereum address: ${validatorAddress}`);
      }

      // Standardiser l'adresse (s'assurer qu'elle a le bon format)
      const formattedAddress = ethers.getAddress(validatorAddress);

      // Vérifier que le type est valide (0, 1 ou 2)
      if (![0, 1, 2].includes(validatorType)) {
        throw new Error(`Invalid validator type: ${validatorType}. Must be 0, 1, or 2.`);
      }

      // Vérifier l'état de la connexion
      if (!this.provider || !this.landRegistry) {
        await this.initializeBlockchain();
      }

      // Vérifier que le signataire est le propriétaire
      const contractOwner = await this.landRegistry.owner();
      const signerAddress = await this.signer.getAddress();

      this.logger.log(`Contract owner: ${contractOwner}`);
      this.logger.log(`Signer address: ${signerAddress}`);

      if (contractOwner.toLowerCase() !== signerAddress.toLowerCase()) {
        throw new Error(`Signer (${signerAddress}) is not the owner (${contractOwner}) of the contract`);
      }

      // Vérifier si le validateur existe déjà
      const isAlreadyValidator = await this.landRegistry.validators(formattedAddress);
      if (isAlreadyValidator) {
        throw new Error(`Address ${formattedAddress} is already registered as a validator`);
      }

      // Estimer le gas nécessaire (avec une marge de sécurité)
      let gasLimit;
      try {
        const estimatedGas = await this.landRegistry.addValidator.estimateGas(
          formattedAddress,
          validatorType
        );
        // Ajouter 20% de marge
        gasLimit = BigInt(Math.floor(Number(estimatedGas) * 1.2));
        this.logger.log(`Estimated gas: ${estimatedGas}, with margin: ${gasLimit}`);
      } catch (error) {
        this.logger.warn(`Failed to estimate gas: ${error.message}`);
        // Fallback à une valeur par défaut plus élevée
        gasLimit = BigInt(500000);
      }

      // Appeler la fonction addValidator du contrat avec plus de détails
      this.logger.log(`Calling addValidator with address: ${formattedAddress}, type: ${validatorType}, gasLimit: ${gasLimit}`);
      const tx = await this.landRegistry.addValidator(formattedAddress, validatorType, {
        gasLimit
      });

      this.logger.log(`Transaction sent: ${tx.hash}`);

      // Attendre la confirmation avec timeout
      const receipt = await Promise.race([
        tx.wait(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Transaction confirmation timeout')), 60000)
        )
      ]);

      // Vérifier le succès de la transaction
      if (receipt.status === 0) {
        throw new Error("Transaction failed");
      }

      this.logger.log(`Validator ${formattedAddress} successfully added with type ${validatorType}`, {
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber
      });

      return {
        success: true,
        data: {
          validatorAddress: formattedAddress,
          validatorType,
          transactionHash: receipt.hash,
          blockNumber: receipt.blockNumber
        },
        message: `Validator ${formattedAddress} successfully added as ${this.getValidatorTypeString(validatorType)}`
      };
    } catch (error) {
      this.logger.error(`Error adding validator ${validatorAddress}:`, error);

      // Log plus détaillé de l'erreur
      if (error.error) {
        this.logger.error('Contract error details:', error.error);
      }

      // Essayer d'extraire plus d'informations sur l'erreur
      let errorMessage = error.message || 'Unknown error';
      let errorCode = error.code || 'UNKNOWN';

      // Gérer spécifiquement les erreurs du contrat
      if (error.message?.includes("execution reverted")) {
        const revertReason = error.error?.data?.message || error.reason || 'Unknown reason';
        errorMessage = `Contract execution reverted: ${revertReason}`;
      }

      if (error.message?.includes("InvalidValidator")) {
        errorMessage = `Invalid validator address: ${validatorAddress}`;
      }

      if (error.message?.includes("UnauthorizedAccount") ||
        error.message?.includes("only owner") ||
        error.message?.includes("Not owner")) {
        errorMessage = "You don't have permission to add validators";
      }

      if (error.code === 'INSUFFICIENT_FUNDS') {
        errorMessage = 'Not enough ETH to pay for gas';
      }

      return {
        success: false,
        error: {
          message: errorMessage,
          code: errorCode,
          originalError: error.message
        },
        message: `Failed to add validator: ${errorMessage}`
      };
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