import { sql } from "drizzle-orm";
import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
// Cuando migres a MySQL, cambiarás a "mysqlTable", "varchar", "timestamp", etc.

// Tabla users
export const users = sqliteTable("users", {
  id: text("id").primaryKey(),                   // usa uuid desde el repo
  username: text("username").notNull().unique(), // normalizado a lowercase antes de insertar
  passwordHash: text("password_hash").notNull(), // bcrypt hash
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(unixepoch())`),                // SQLite: segundos unix
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(unixepoch())`),
});
