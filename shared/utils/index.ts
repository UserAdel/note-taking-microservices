import { ApiResponse } from "../types";

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
