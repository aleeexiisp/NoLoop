import crypto from 'node:crypto';

import DBLocal from 'db-local';
import { z } from 'zod';
import bcrypt from 'bcrypt';

import { SALT_ROUNDS } from '../../../config/config.js';
const { Schema } = new DBLocal({ path: './db'});

// Validación y normalización de username + password con Zod
const CreateUserSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "El usuario debe tener al menos 3 caracteres")
    .max(32, "El usuario no puede superar 32 caracteres")
    .regex(/^[A-Za-z][A-Za-z0-9._-]*$/, "Debe empezar por letra y solo usar letras, números, . _ -")
    .transform((v) => v.toLowerCase()),
  password: z
    .string()
    .min(10, "La contraseña debe tener al menos 10 caracteres")
    .max(128, "La contraseña no puede superar 128 caracteres")
    .regex(/[a-z]/, "Debe incluir al menos una minúscula")
    .regex(/[A-Z]/, "Debe incluir al menos una mayúscula")
    .regex(/[0-9]/, "Debe incluir al menos un número")
    .regex(/[^A-Za-z0-9]/, "Debe incluir al menos un símbolo"),
});

type CreateUserInput = z.input<typeof CreateUserSchema>;
//type CreateUserData  = z.output<typeof CreateUserSchema>;

const User = Schema('User', {
    _id: { type: String, default: () => crypto.randomUUID(), primary: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
})

// Tipo para usuario sin password
type SafeUser = Omit<typeof User.schema, 'password'> & { password?: never };

// Función para quitar la password
function omitPassword(user: any): SafeUser {
    const { password, ...safeUser } = user;
    return safeUser;
}

export interface UserRepository {
    create(input: CreateUserInput): Promise<string>;
    login(input: CreateUserInput): Promise<any>;
}

export const userRepository: UserRepository = {
    async create(input: CreateUserInput) {
        // 1. Validaciones de username con zod
        const {username, password } = CreateUserSchema.parse(input);

        // 2. Validar que no exista otro usuario con ese username
        const user = User.findOne({ username });
        if (user) throw new Error('El usuario ya existe');

        // 3. Crear el usuario
        const id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        User.create({
            _id: id,
            username,
            password: hashedPassword,
        }).save();

        return id;
    },
    async login(input: CreateUserInput) {
        // 1. Validaciones de username con zod
        const {username, password } = CreateUserSchema.parse(input);

        // 2. Buscar el usuario por username
        const user = User.findOne({ username });
        if (!user) throw new Error('Usuario o contraseña incorrecta');

        // 3. Comparar la password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) throw new Error('Usuario o contraseña incorrecta');

        return omitPassword(user);
    },
};
