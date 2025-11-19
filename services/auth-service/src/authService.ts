import { AuthToken } from "@shared/types";
import prisma from "./database";
import { createServiceError } from "@shared/utils";
import bcrypt from "bcryptjs";
import jwt, { SignOptions } from "jsonwebtoken";
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
}
