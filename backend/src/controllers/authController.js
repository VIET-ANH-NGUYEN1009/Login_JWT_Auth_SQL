// @ts-nocheck
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import pool from "../libs/db.js";

const ACCESS_TOKEN_TTL = "30m";
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 ngày

// =================== SIGN UP ===================
export const signUp = async (req, res) => {
  const client = await pool.connect();
  try {
    const { username, password, email, firstName, lastName } = req.body;

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({ message: "Thiếu thông tin bắt buộc" });
    }

    // kiểm tra username tồn tại
    const duplicate = await client.query(
      `SELECT id FROM "Users" WHERE username = $1`,
      [username],
    );

    if (duplicate.rows.length > 0) {
      return res.status(409).json({ message: "Username đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const displayName = `${firstName} ${lastName}`;

    await client.query(
      `
      INSERT INTO "Users" (username, email, "displayName", "hashedPassword")
      VALUES ($1, $2, $3, $4)
      `,
      [username, email, displayName, hashedPassword],
    );

    return res.sendStatus(204);
  } catch (error) {
    console.error("❌ Lỗi signUp:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  } finally {
    client.release();
  }
};

// =================== SIGN IN ===================

export const signIn = async (req, res) => {
  const client = await pool.connect();
  try {
    const { Username, Password } = req.body;

    if (!Username || !Password) {
      return res.status(400).json({ message: "Thiếu username hoặc password" });
    }

    const result = await client.query(
      `SELECT * FROM "UserInfor" WHERE "Username" = $1`,
      [Username],
    );

    const user = result.rows[0];
    if (!user || user.Password !== Password) {
      return res.status(401).json({
        message: "Username hoặc password không chính xác",
      });
    }

    // Tạo access token
    const accessToken = jwt.sign(
      { username: user.Username },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" },
    );

    // Tạo refresh token
    const refreshToken = crypto.randomBytes(64).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    // Update refresh token (KHÔNG ON CONFLICT)
    await client.query(
      `
      UPDATE "UserInfor"
      SET "refreshToken" = $2,
          "expiresAt" = $3
      WHERE "Username" = $1
      `,
      [user.Username, refreshToken, expiresAt],
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false, // localhost
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: `User ${user.Username} đã đăng nhập`,
      accessToken,
    });
  } catch (error) {
    console.error("❌ Lỗi signIn:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  } finally {
    client.release();
  }
};

// =================== SIGN OUT ===================
export const signOut = async (req, res) => {
  const client = await pool.connect();
  try {
    const token = req.cookies?.refreshToken;

    if (token) {
      await client.query(
        `UPDATE "UserInfor"
SET "refreshToken" = NULL,
    "expiresAt" = NULL
WHERE "refreshToken" = $1;`,
        [token],
      );
      res.clearCookie("refreshToken");
    }

    return res.sendStatus(204);
  } catch (error) {
    console.error("❌ Lỗi signOut:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  } finally {
    client.release();
  }
};

// =================== REFRESH TOKEN ===================
export const refreshToken = async (req, res) => {
  const client = await pool.connect();
  try {
    const token = req.cookies?.refreshToken;
    if (!token) {
      return res.status(401).json({ message: "Token không tồn tại" });
    }

    const result = await client.query(
      `SELECT * FROM "UserInfor" WHERE "refreshToken" = $1`,
      [token],
    );

    const session = result.rows[0];
    if (!session) {
      return res
        .status(403)
        .json({ message: "Token không hợp lệ hoặc đã hết hạn" });
    }

    if (new Date(session.expiresAt) < new Date()) {
      return res.status(403).json({ message: "Token đã hết hạn" });
    }

    const accessToken = jwt.sign(
      { username: session.Username },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL },
    );

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error("❌ Lỗi refreshToken:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  } finally {
    client.release();
  }
};
