import { User } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserEntity implements User {
  id!: string;
  email!: string;
  name!: string | null;

  @Exclude()
  passwordHash!: string;

  constructor(user: User) {
    Object.assign(this, user);
  }
}
