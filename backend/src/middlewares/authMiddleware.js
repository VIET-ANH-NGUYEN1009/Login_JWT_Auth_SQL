import jwt from "jsonwebtoken";
import pool from "../libs/db.js";

export const protectedRoute = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Không có access token" });
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const result = await pool.query(
      `SELECT "Username" FROM "UserInfor" WHERE "Username" = $1`,
      [decoded.username],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "User không tồn tại" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("❌ authMiddleware:", error);
    return res.status(403).json({ message: "Token không hợp lệ" });
  }
};
