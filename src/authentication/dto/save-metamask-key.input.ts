import { Field, InputType } from '@nestjs/graphql';
import { IsEthereumAddress, IsNotEmpty } from 'class-validator';

@InputType()
export class SaveMetamaskKeyInput {
  @Field()
  @IsEthereumAddress()
  @IsNotEmpty()
  publicKey: string;
}