import { ApiResponse, ServiceError } from "../types";

export function createApiResponse<T>(
  success: boolean,
  data?: T,
  message?: string,
  error?: string,
  errors?: Record<string, string[]>
): ApiResponse<T> {
  return {
    success,
    data,
    message,
    error,
    errors,
  };
}
export function createServiceError(
  message: string,
  statusCode: number = 500,
  code?: string,
  details?: any
): ServiceError {
  return new ServiceError(message, statusCode, code, details);
}
