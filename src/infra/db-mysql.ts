import mysql from "mysql2/promise";
import { drizzle } from "drizzle-orm/mysql2";

export async function makeMySqlDb() {
  const pool = mysql.createPool({
    host: process.env.MYSQL_HOST!,
    user: process.env.MYSQL_USER!,
    password: process.env.MYSQL_PASSWORD!,
    database: process.env.MYSQL_DB!,
    waitForConnections: true,
    connectionLimit: 10,
  });
  return drizzle(pool);
}
