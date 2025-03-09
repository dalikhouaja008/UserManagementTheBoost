import { Field, ObjectType } from "@nestjs/graphql";
import { DeviceInfo } from "../responses/deviceInfo.response";

@ObjectType()
export class Session {
  @Field(() => String)
  id: string;

  @Field(() => DeviceInfo)
  deviceInfo: DeviceInfo;

  @Field(() => String)
  createdAt: string;

  @Field(() => String)
  lastActive: string;
}