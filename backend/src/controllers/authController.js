// @ts-nocheck
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import sql from "mssql";

const ACCESS_TOKEN_TTL = "30m";
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 ngày

export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body;
    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({ message: "Thiếu thông tin bắt buộc" });
    }

    // kiểm tra username tồn tại chưa
    const duplicate =
      await sql.query`SELECT * FROM Users WHERE username = ${username}`;
    if (duplicate.recordset.length > 0) {
      return res.status(409).json({ message: "username đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await sql.query`
      INSERT INTO Users (username, email, displayName, hashedPassword)
      VALUES (${username}, ${email}, ${firstName + " " + lastName}, ${hashedPassword})
    `;

    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi signUp:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const signIn = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Thiếu username hoặc password" });
    }

    const result =
      await sql.query`SELECT * FROM Users WHERE username = ${username}`;
    const user = result.recordset[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "username hoặc password không chính xác" });
    }

    const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);
    if (!passwordCorrect) {
      return res
        .status(401)
        .json({ message: "username hoặc password không chính xác" });
    }

    const accessToken = jwt.sign(
      { userId: user.id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL },
    );

    const refreshToken = crypto.randomBytes(64).toString("hex");

    await sql.query`
      INSERT INTO Sessions (userId, refreshToken, expiresAt)
      VALUES (${user.id}, ${refreshToken}, ${new Date(Date.now() + REFRESH_TOKEN_TTL)})
    `;

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: REFRESH_TOKEN_TTL,
    });

    return res
      .status(200)
      .json({ message: `User ${user.displayName} đã logged in!`, accessToken });
  } catch (error) {
    console.error("Lỗi signIn:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const signOut = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (token) {
      await sql.query`DELETE FROM Sessions WHERE refreshToken = ${token}`;
      res.clearCookie("refreshToken");
    }
    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi signOut:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (!token)
      return res.status(401).json({ message: "Token không tồn tại." });

    const result =
      await sql.query`SELECT * FROM Sessions WHERE refreshToken = ${token}`;
    const session = result.recordset[0];
    if (!session)
      return res
        .status(403)
        .json({ message: "Token không hợp lệ hoặc đã hết hạn" });

    if (new Date(session.expiresAt) < new Date()) {
      return res.status(403).json({ message: "Token đã hết hạn." });
    }

    const accessToken = jwt.sign(
      { userId: session.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL },
    );

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error("Lỗi refreshToken:", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
