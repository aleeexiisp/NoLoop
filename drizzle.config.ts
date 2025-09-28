import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./src/adapters/db/schema.ts",
  out: "./drizzle",                 // carpeta de migraciones
  dialect: "sqlite",                // hoy usamos sqlite
  dbCredentials: {
    url: "file:./db/noloop.db",     // archivo sqlite (asegúrate de que la carpeta db exista)
  },
});

/*
Cuando MySQL, este archivo quedaría así:

export default defineConfig({
  schema: "./src/adapters/db/schema.ts",
  out: "./drizzle",
  dialect: "mysql",
  dbCredentials: {
    // Usa variables de entorno reales
    host: process.env.MYSQL_HOST!,
    user: process.env.MYSQL_USER!,
    password: process.env.MYSQL_PASSWORD!,
    database: process.env.MYSQL_DB!,
  },
});
*/
