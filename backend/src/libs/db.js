import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_SERVER || "localhost",
  database: process.env.DB_NAME || "User",
  password: process.env.DB_PASS || "Vietanh12345@",
  port: process.env.DB_PORT || 5432,
  ssl: false, // true nếu deploy cloud
});

export const connectDB = async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Kết nối PostgreSQL thành công!");
    client.release();
  } catch (error) {
    console.error("❌ Lỗi khi kết nối PostgreSQL:", error);
    process.exit(1);
  }
};

export default pool;
