// @ts-nocheck
import jwt from "jsonwebtoken";
import sql from "mssql";

export const protectedRoute = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

    if (!token) {
      return res.status(401).json({ message: "Không tìm thấy access token" });
    }

    jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET,
      async (err, decodedUser) => {
        if (err) {
          console.error(err);
          return res
            .status(403)
            .json({ message: "Access token hết hạn hoặc không đúng" });
        }

        try {
          // Query SQL Server để tìm user theo id
          const result = await sql.query`
          SELECT id, email, username 
          FROM Users 
          WHERE id = ${decodedUser.userId}
        `;

          const user = result.recordset[0];

          if (!user) {
            return res
              .status(404)
              .json({ message: "Người dùng không tồn tại." });
          }

          // gắn user vào req
          req.user = user;
          next();
        } catch (dbErr) {
          console.error("Lỗi khi truy vấn SQL:", dbErr);
          return res.status(500).json({ message: "Lỗi hệ thống" });
        }
      },
    );
  } catch (error) {
    console.error("Lỗi khi xác minh JWT trong authMiddleware", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
