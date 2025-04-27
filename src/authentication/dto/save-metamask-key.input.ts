import { Field, InputType } from '@nestjs/graphql';
import { IsEthereumAddress, IsNotEmpty, IsString } from 'class-validator';

@InputType()
export class SaveMetamaskKeyInput {
  @Field()
  @IsEthereumAddress()
  @IsNotEmpty()
  ethereumAddress: string;

  @Field()
  @IsString()
  @IsNotEmpty()
  publicKey: string;
}