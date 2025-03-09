import { Catch, RpcExceptionFilter } from "@nestjs/common";
import { of } from "rxjs";

@Catch()
export class MicroserviceExceptionFilter implements RpcExceptionFilter<Error> {
  catch(exception: Error) {
    return of({
      success: false,
      error: exception.message,
      timestamp: new Date().toISOString()
    });
  }
}