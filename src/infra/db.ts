import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "../adapters/db/schema.js";

// 1) Conexión a SQLite
export const sqlite: any = new Database("./db/noloop.db");

// 2) Configuración recomendada para concurrencia y durabilidad
sqlite.pragma("journal_mode = WAL");  // mejor concurrencia en lecturas/escrituras
sqlite.pragma("foreign_keys = ON");   // por si añades FKs

// 3) Instancia Drizzle
export const db = drizzle(sqlite, { schema });