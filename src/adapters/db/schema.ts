import { sql } from "drizzle-orm";
import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
// Cuando migres a MySQL, cambiar a "mysqlTable", "varchar", "timestamp", etc.

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


// Tabla refresh_tokens
export const refreshTokens = sqliteTable("refresh_tokens", {
  jti: text("jti").primaryKey(),                         // id del refresh
  userId: text("user_id").notNull(),                     // referencia a users.id
  tokenHash: text("token_hash").notNull(),               // hash del secreto del refresh
  revoked: integer("revoked").notNull().default(0),      // 0/1
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(unixepoch())`),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
});


// Tabla para tokens de reseteo de password
export const passwordResetTokens = sqliteTable("password_reset_tokens", {
  id: text("id").primaryKey(),                                // uuid
  userId: text("user_id").notNull(),
  tokenHash: text("token_hash").notNull(),                    // guarda SOLO el hash del token
  createdAt: integer("created_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(unixepoch())`),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(), // Date
  usedAt: integer("used_at", { mode: "timestamp" }),                 // null si no usado
});