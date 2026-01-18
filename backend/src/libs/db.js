import sql from "mssql";

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_SERVER, // ví dụ: "localhost"
  database: process.env.DB_NAME,
  options: {
    encrypt: true, // nếu dùng Azure
    trustServerCertificate: true, // nếu chạy local
  },
};

export const connectDB = async () => {
  try {
    await sql.connect(config);
    console.log("✅ Liên kết SQL Server thành công!");
  } catch (error) {
    console.error("❌ Lỗi khi kết nối SQL Server:", error);
    process.exit(1);
  }
};
