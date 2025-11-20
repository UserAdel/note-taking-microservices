import { AuthToken, JWTPayload, ServiceError } from "../../../shared/types";
import prisma from "./database";
import { createServiceError } from "../../../shared/utils";
import bcrypt from "bcryptjs";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import ms, { type StringValue } from "ms";

export class AuthService {
  private readonly jwtSecret: string;
  private readonly jwtRefreshSecret: string;
  private readonly jwtExpiresIn: string;
  private readonly jwtRefreshExpiresIn: string;
  private readonly bcryptRounds: number;
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET!;
    this.jwtRefreshSecret = process.env.JWT_REFRESH_SECRET!;
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN! || "15m";
    this.jwtRefreshExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN! || "7d";
    this.bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || "10", 10);
    if (!this.jwtSecret || !this.jwtRefreshSecret) {
      throw new Error("JWT secrets are not defined in envirement variables");
    }
  }
  async register(email: string, password: string): Promise<AuthToken> {
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });
    if (existingUser) {
      throw createServiceError("User already exists", 409);
    }

    const hashedPassword = await bcrypt.hash(password, this.bcryptRounds);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
    return this.genertateTokens(user.id, user.email);
  }

  async login(email: string, password: string): Promise<AuthToken> {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (!user || user.password) {
      throw createServiceError("Invalid email or password", 400);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw createServiceError("Invalid Email or password", 401);
    }
    return this.genertateTokens(user.id, user.email);
  }

  async refreshToken(refreshToken: string): Promise<AuthToken> {
    try {
      const decode = jwt.verify(
        refreshToken,
        this.jwtRefreshSecret
      ) as JWTPayload;
      const storedToken = await prisma.refreshToken.findUnique({
        where: {
          token: refreshToken,
        },
        include: {
          user: true,
        },
      });
      if (!storedToken || storedToken.expiresAt < new Date()) {
        throw createServiceError("invalid or expired refresh token", 401);
      }
      const token = await this.genertateTokens(
        storedToken.user.id,
        storedToken.user.email
      );
      await prisma.refreshToken.delete({
        where: {
          id: storedToken.id,
        },
      });
      return token;
    } catch (error) {
      if (error instanceof ServiceError) {
        throw error;
      }
      throw createServiceError("Invalid refresh token", 401, error);
    }
  }

  async logout(refreshToken: string): Promise<void> {
    await prisma.refreshToken.deleteMany({
      where: {
        token: refreshToken,
      },
    });
  }
  async validateToken(token: string): Promise<JWTPayload> {
    try {
      const decode = jwt.verify(token, this.jwtSecret) as JWTPayload;
      const user = await prisma.user.findMany({
        where: {
          id: decode.userId,
        },
      });
      if (!user) {
        throw createServiceError("User not found", 4004);
      }
      return decode;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw createServiceError("Invalid Token ", 401);
      }
      throw createServiceError("Token validation faild", 500, error);
    }
  }
  private async genertateTokens(
    userId: string,
    email: string
  ): Promise<AuthToken> {
    const payload = { userId, email };
    const accessTokenOptions: SignOptions = {
      expiresIn: this.jwtExpiresIn as StringValue,
    };
    const accessToken = jwt.sign(
      payload,
      this.jwtSecret,
      accessTokenOptions
    ) as string;
    //Generate refresh token
    const refreshTokenOptions: SignOptions = {
      expiresIn: this.jwtRefreshExpiresIn as StringValue,
    };
    const refreshToken = jwt.sign(
      payload,
      this.jwtRefreshSecret,
      refreshTokenOptions
    ) as string;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    await prisma.refreshToken.create({
      data: {
        userId,
        token: refreshToken,
        expiresAt,
      },
    });
    return {
      accessToken,
      refreshToken,
    };
  }

  async getUserById(userId: string) {
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!user) {
      throw createServiceError("User not Found", 404);
    }
    return user;
  }
  async deleteUser(userId: string): Promise<void> {
    await prisma.user.delete({
      where: {
        id: userId,
      },
    });
  }
}
