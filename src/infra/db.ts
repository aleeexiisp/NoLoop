import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "../adapters/db/schema.js";
import { SQLITE_PATH } from "../../config/config.js";

// 1) Conexión a SQLite
const dbFile = SQLITE_PATH;

if (dbFile !== ":memory:" && dbFile !== "" && !dbFile.startsWith("file:")) {
  const dir = path.dirname(dbFile);
  if (dir && dir !== ".") {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export const sqlite: any = new Database(dbFile);

// 2) Configuración recomendada para concurrencia y durabilidad
sqlite.pragma("journal_mode = WAL");  // mejor concurrencia en lecturas/escrituras
sqlite.pragma("foreign_keys = ON");   // por si añades FKs

// 3) Instancia Drizzle
export const db = drizzle(sqlite, { schema });
