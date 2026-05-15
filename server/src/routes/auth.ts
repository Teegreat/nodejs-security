import express from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
import bcrypt from "bcrypt";
import {
  clearAuthCookies,
  requireCsrf,
  setAuthCookies,
} from "../utils/cookie.js";
import { use } from "passport";
import { requireAccessAuth, requiredRole } from "../middleware/auth.js";
import { AuthenticatedRequest, AuthTokenPayload } from "../utils/types.js";
import {
  clearFailedLoginAttempts,
  isAccLocked,
  registerFailedLoginAttempt,
  validateBody,
} from "../utils/helpers.js";
import {
  listUsersQuerySchema,
  loginSchema,
  registerSchema,
} from "../schema.js";

const router = express.Router();

const EXTRACT_SAFE_USER_SELECT_OPTIONS = "-password";

// POST /api/auth/register
router.post("/register", validateBody(registerSchema), async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashPassword,
    });

    res.status(201).json({
      message: "User created",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({
      message: "Register failed",
      error,
    });
  }
});

// POST /api/auth/login
router.post("/login", validateBody(loginSchema), async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // check if account is locked
    if (isAccLocked(user)) {
      return res.status(429).json({
        message: "Too many login attempts. Please try again later",
      });
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      await registerFailedLoginAttempt(user);

      if (isAccLocked(user)) {
        return res.status(429).json({
          message: "Too many login attempts. Please try again later",
        });
      }

      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    await clearFailedLoginAttempts(user);

    // set auth cookies
    setAuthCookies(res, String(user._id), user.role);

    res.json({
      message: "Login success",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({
      message: "Login failed",
      error,
    });
  }
});

// GET /api/auth/me
router.get("/me", requireAccessAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const user = await User.findById(req.authUser?.userId).select(
      EXTRACT_SAFE_USER_SELECT_OPTIONS,
    );

    if (!user) {
      res.status(404).json({
        message: "User not found",
      });
    }

    return res.json(user);
  } catch (error) {
    res.status(401).json({
      message: "Unauthorized",
      error,
    });
  }
});

router.post("/refresh", requireCsrf, async (req, res) => {
  try {
    const refreshToken = req.cookies?.["refresh_token"];

    if (!refreshToken) {
      return res.status(401).json({
        message: "No refresh token",
      });
    }

    const decodedUserInfo = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET!,
    ) as AuthTokenPayload;

    if (decodedUserInfo.type !== "refresh") {
      return res.status(401).json({
        message: "Invalid refresh token",
      });
    }

    setAuthCookies(res, decodedUserInfo.userId, decodedUserInfo.role);

    return res.json({
      message: "Token refreshed",
    });
  } catch (error) {
    return res.status(401).json({
      message: "Refresh failed",
    });
  }
});

router.post("/logout", requireCsrf, (_req, res) => {
  clearAuthCookies(res);
  return res.json({ message: "Logout success" });
});

router.get(
  "/users",
  requireAccessAuth,
  requiredRole("admin"),
  async (req, res) => {
    try {
      const pasrsedQuery = listUsersQuerySchema.safeParse(req.query);

      if (!pasrsedQuery.success) {
        return res.status(400).json({
          message: "Invalid query filters",
        });
      }

      const filters: Record<string, string> = {};

      if (pasrsedQuery.data.role) {
        filters.role = pasrsedQuery.data.role;
      }

      if (pasrsedQuery.data.name) {
        filters.name = pasrsedQuery.data.name;
      }

      if (pasrsedQuery.data.email) {
        filters.email = pasrsedQuery.data.email;
      }

      const extractUsersList = await User.find(filters).select(
        EXTRACT_SAFE_USER_SELECT_OPTIONS,
      );

      return res.json({ users: extractUsersList });
    } catch (error) {
      return res.status(500).json({
        message: "Failed to fetch users list",
      });
    }
  },
);

export default router;
