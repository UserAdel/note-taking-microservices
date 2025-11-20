import { Router } from "express";
import * as authController from "./authController";
import { authenticationToken, validateRequest } from "../../../shared/middleware";
import { loginSchema, refreshTokenSchema, registerSchema } from "./validation";

const router = Router();

router.post(
  "/register",
  validateRequest(registerSchema),
  authController.register
);

router.post("/login", validateRequest(loginSchema), authController.login);
router.post(
  "/refresh",
  validateRequest(refreshTokenSchema),
  authController.refreshToken
);

router.post(
  "/logout",
  validateRequest(refreshTokenSchema),
  authController.logut
);
router.post("/validate", authController.validateToken);
// Protected routes
router.get("/profile", authenticationToken,authController.getProfile);
router.delete("/profile", authenticationToken,authController.deleteAccount);
export default router;
