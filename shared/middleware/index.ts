import { Request, Response, NextFunction } from "express";
import { JWTPayload, logError, ServiceError } from "../types";
import { createErrorResponse } from "../utils/index";
import jwt from "jsonwebtoken";
//extend express Request interface to include cutom properties
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

export function authenticateToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json(createErrorResponse("No token provided"));
  }
  const jwtSecret = process.env.JWT_SECRET!;
  if (!jwtSecret) {
    logError(new Error("JWT_SECRET is not definded"));
    return res.status(500).json(createErrorResponse("Internal server error"));
  }
  const decoded = jwt.verify(token, jwtSecret, (err: any, decoded: any) => {
    if (err) {
      return res.status(401).json(createErrorResponse("Invalid token"));
    }
    req.user = decoded as JWTPayload;
    next();
  });
}

export type RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => void;

export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

export function validateRequest(schema: any): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(req.body);
    if (error) {
      const errors: Record<string, string[]> = {};
      error.details.forEach((detail: any) => {
        const field = detail.path.join(".");
        if (!errors[field]) {
          errors[field] = [];
        }
        errors[field].push(detail.message);
      });

      res.status(400).json({
        success: false,
        message: "Validation error",
        errors,
      });
      return;
    }
    next();
  };
}

export function errorHandler(
  error: ServiceError,
  req: Request,
  res: Response,
  next: NextFunction
) {
  logError(error, {
    method: req.method,
    url: req.url,
    body: req.body,
    params: req.params,
    query: req.query,
  });
  const statusCode = error.statusCode || 500;
  const message = error.message || "Internal Server Error";
  res.status(statusCode).json(createErrorResponse(message));
}

export function corsOptions() {
  return {
    origin: process.env.CORS_ORIGIN || "*",
    credentails: process.env.CORS_CREDENTIALS,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  };
}
