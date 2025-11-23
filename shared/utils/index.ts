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
export function createSuccessResponse<T>(
  data: T,
  message?: string
): ApiResponse<T> {
  return createApiResponse(true, data, message);
}

export function createErrorResponse(
  error: string,
  message?: string
): ApiResponse<null> {
  return createApiResponse(false, null, undefined, error);
}
export function createServiceError(
  message: string,
  statusCode: number = 500,
  code?: string,
  details?: any
): ServiceError {
  return new ServiceError(message, statusCode, code, details);
}

export function sanitizeInput(input: string) {
  return input.replace(/[<>]/g, "").trim();
}
