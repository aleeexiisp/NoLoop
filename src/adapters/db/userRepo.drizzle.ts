import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "../../infra/db.js";
import { users, refreshTokens } from "./schema.js";
import { sql } from "drizzle-orm";

import { z } from "zod";
import { REFRESH_TTL_SEC, SALT_ROUNDS } from "../../../config/config.js";

/*********************************
 * 
 *      ZOD SCHEMA VALIDATIONS
 * 
 *********************************/

// Schema de validación de username con zod
const UsernameSchema = z
    .string()
    .trim()
    .min(3, "El usuario debe tener al menos 3 caracteres")
    .max(32, "El usuario no puede superar 32 caracteres")
    .regex(/^[A-Za-z][A-Za-z0-9._-]*$/, "Debe empezar por letra y solo usar letras, números, . _ -")
    .transform(v => v.toLowerCase());

const PasswordSchema = z
    .string()
    .min(10, "La contraseña debe tener al menos 10 caracteres")
    .max(128, "La contraseña no puede superar 128 caracteres")
    .regex(/[a-z]/, "Debe incluir al menos una minúscula")
    .regex(/[A-Z]/, "Debe incluir al menos una mayúscula")
    .regex(/[0-9]/, "Debe incluir al menos un número")
    .regex(/[^A-Za-z0-9]/, "Debe incluir al menos un símbolo");

// Schema de validación de username y password con zod para el register
const RegisterSchema = z.object({
    username: UsernameSchema,
    password: PasswordSchema,
});

// Schema de validación de username y password simple con zod para el login
const LoginSchema = z.object({
    username: UsernameSchema,
    password: z
        .string()
        .min(1),
});

const NewPassSchema = z.object({
    userId: z
        .string()
        .min(1),
    currentPassword: z
        .string()
        .min(1),
    newPassword: PasswordSchema
});

/*********************************
 * 
 *      HELPER FUNCTIONS
 * 
 *********************************/

export type SafeUser = { id: string; username: string; createdAt: Date; updatedAt: Date };

const rowToSafeUser = (row: any): SafeUser => ({
  id: row.id,
  username: row.username,
  createdAt: new Date(row.createdAt * 1000), // epoch -> Date
  updatedAt: new Date(row.updatedAt * 1000),
});

const nowSec = () => Math.floor(Date.now() / 1000);

/*********************************
 * 
 *      CLASS / REPOSITORY
 * 
 *********************************/

export interface UserRepository {
    // Gestión de usuarios
    create(input: z.input<typeof RegisterSchema>): Promise<string>;
    login(input: z.input<typeof LoginSchema>): Promise<{ id: string; username: string }>;
    changePassword(input: z.input<typeof NewPassSchema>): Promise<void>;

    // Gestión de refresh tokens
    issueRefresh(userId: string): Promise<{ jti: string; token: string; expiresAt: number }>;
    rotateRefresh(oldToken: string): Promise<{ jti: string; token: string; expiresAt: number }>;
    revokeRefresh(tokenOrJti: string): Promise<void>;
    revokeAllRefresh(userId: string): Promise<void>;
}

export const userRepository = {
    async create(input: z.input<typeof RegisterSchema>): Promise<string> {
        // 1. Validaciones de username con zod
        const {username, password } = RegisterSchema.parse(input);

        // 2. Validar que no exista otro usuario con ese username
        const exists = await db.query.users.findFirst({ where: eq(users.username, username) });
        if (exists) {
            const e: any = new Error("El usuario ya existe");
            e.statusCode = 409;
            throw e;
        }

        // 3. Crear el usuario
        const id = crypto.randomUUID();
        const passwordHash  = await bcrypt.hash(password, Number(SALT_ROUNDS));

        await db.insert(users).values({
            id,
            username,
            passwordHash
        })

        return id;
    },
    async login(input: z.input<typeof LoginSchema>): Promise<SafeUser> {
        // 1. Validaciones de username con zod
        const {username, password } = LoginSchema.parse(input);

        // 2. Buscar el usuario por username
        const row = await db.query.users.findFirst({ where: eq(users.username, username) });
        if (!row) throw new Error('Usuario o contraseña incorrecta');

        // 3. Comparar la password
        const isPasswordValid = await bcrypt.compare(password, row.passwordHash);
        if (!isPasswordValid) throw new Error('Usuario o contraseña incorrecta');

        return rowToSafeUser(row);
    },
    async changePassword(input: z.input<typeof NewPassSchema>): Promise<void> {
        const { userId, currentPassword, newPassword } = NewPassSchema.parse(input);

        // 1. Validar que el usuario exista
        const user = await db.query.users.findFirst({ where: eq(users.id, userId) });
        if (!user) throw new Error('Usuario no encontrado');

        // 2. Validar password actual
        const isPasswordValid = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!isPasswordValid) throw new Error('Contraseña actual incorrecta');

        // 3. Validar la nueva password
        const hash = await bcrypt.hash(newPassword, Number(SALT_ROUNDS));

        // 4. Actualizar la password en la DB
        await db
            .update(users)
            .set({
                passwordHash: hash,
                updatedAt: sql`(unixepoch())`,
            })
            .where(eq(users.id, userId));
    },
    async issueRefresh(userId: string): Promise<{ jti: string; token: string; expiresAt: number }> {
        // TTL dinámico por llamada
        const expSec = nowSec() + Number(REFRESH_TTL_SEC);

        const jti = crypto.randomUUID();
        const secret = crypto.randomBytes(32).toString("hex");
        const token = `${jti}.${secret}`;
        const tokenHash = await bcrypt.hash(secret, Number(SALT_ROUNDS));

        // Si en schema expiresAt es { mode:"timestamp" }, guarda Date:
        const expiryDate = new Date(expSec * 1000);

        await db.insert(refreshTokens).values({
        jti,
        userId,
        tokenHash,
        expiresAt: expiryDate, // Drizzle -> Date (timestamp)
        });

        // Devuelve epoch seconds para usar fácil en cookies
        return { jti, token, expiresAt: expSec };
    },

    async rotateRefresh(oldToken: string): Promise<{
        user: { id: string; username: string },
        refresh: { token: string; expiresAt: number }
    }> {
        const parts = oldToken.split(".");
        if (parts.length !== 2) {
        const e: any = new Error("Invalid refresh token");
        e.statusCode = 400; throw e;
        }
        const [jti, secret] = parts as [string, string];

        const row = await db.query.refreshTokens.findFirst({
        where: eq(refreshTokens.jti, jti),
        });
        // row.expiresAt es Date si tu schema usa { mode:"timestamp" }
        if (!row || row.revoked || row.expiresAt <= new Date()) {
        const e: any = new Error("Invalid or expired refresh");
        e.statusCode = 401; throw e;
        }

        const ok = await bcrypt.compare(secret, row.tokenHash);
        if (!ok) {
        const e: any = new Error("Invalid refresh token");
        e.statusCode = 401; throw e;
        }

        // Revoca el viejo
        await db.update(refreshTokens)
        .set({ revoked: 1 })
        .where(eq(refreshTokens.jti, jti));

        // Crea el nuevo y obtén sus datos
        const { token, expiresAt } = await this.issueRefresh(row.userId);

        // Carga usuario para firmar access en server (sin que server toque DB)
        const u = await db.query.users.findFirst({ where: eq(users.id, row.userId) });
        if (!u) { const e: any = new Error("User not found"); e.statusCode = 404; throw e; }

        return { user: { id: u.id, username: u.username }, refresh: { token, expiresAt } };
    },

    async revokeRefresh(tokenOrJti: string): Promise<void> {
        const jti = tokenOrJti.includes(".") ? tokenOrJti.split(".")[0] : tokenOrJti;
        await db.update(refreshTokens)
        .set({ revoked: 1 })
        .where(eq(refreshTokens.jti, jti as string));
    },

    async revokeAllRefresh(userId: string): Promise<void> {
        await db.update(refreshTokens)
        .set({ revoked: 1 })
        .where(eq(refreshTokens.userId, userId));
    },
};
