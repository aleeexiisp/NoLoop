export const {
    PORT = 3000,
    SALT_ROUNDS = 10, // Prod = 10, Dev = 4
    SECRET_JWT_KEY = "b4a11469922c1ec4849234449b1d905d",
} = process.env;