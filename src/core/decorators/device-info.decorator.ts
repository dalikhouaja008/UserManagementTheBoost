import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import DeviceDetector from 'device-detector-js';

export const DeviceInfo = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    
    const deviceDetector = new DeviceDetector();
    const userAgent = request.headers['user-agent'];
    const deviceInfo = deviceDetector.parse(userAgent);

    return {
      userAgent,
      ip: request.ip || request.connection.remoteAddress,
      device: deviceInfo.device?.type || 'unknown',
      browser: deviceInfo.client?.name || 'unknown',
      os: deviceInfo.os?.name || 'unknown'
    };
  },
);