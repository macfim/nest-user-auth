import { registerAs } from '@nestjs/config';

export default registerAs('main', () => ({
  NODE_ENV: process.env.NODE_ENV,
  host: process.env.DATABASE_HOST,
  port: process.env.DATABASE_PORT || 3000,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
}));
