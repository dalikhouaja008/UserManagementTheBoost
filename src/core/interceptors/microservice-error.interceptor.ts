import { CallHandler, ExecutionContext, Injectable, NestInterceptor, ServiceUnavailableException } from "@nestjs/common";
import { Observable } from "rxjs/internal/Observable";
import { TimeoutError } from "rxjs/internal/operators/timeout";
import { catchError } from "rxjs/operators";

@Injectable()
export class MicroserviceErrorInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError(error => {
        if (error instanceof TimeoutError) {
          throw new ServiceUnavailableException('Service timeout');
        }
        throw error;
      }),
    );
  }
}