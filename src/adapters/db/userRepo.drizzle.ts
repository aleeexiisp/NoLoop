import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "../../infra/db.js";
import { users } from "./schema.js";
import { sql } from "drizzle-orm";

import { z } from "zod";
import { SALT_ROUNDS } from "../../../config/config.js";

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

export type SafeUser = { id: string; username: string; createdAt: Date; updatedAt: Date };

const rowToSafeUser = (row: any): SafeUser => ({
  id: row.id,
  username: row.username,
  createdAt: new Date(row.createdAt * 1000), // epoch -> Date
  updatedAt: new Date(row.updatedAt * 1000),
});

export interface UserRepository {
  create(input: z.input<typeof RegisterSchema>): Promise<string>;
  login(input: z.input<typeof LoginSchema>): Promise<{ id: string; username: string }>;
  changePassword(input: z.input<typeof NewPassSchema>): Promise<void>;
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
};
