import { Injectable } from '@nestjs/common';
import type { Prisma, User } from '@prisma/client';
import type { DefaultArgs } from '@prisma/client/runtime/library';
import { DatabaseService } from 'src/database/database.service';

@Injectable()
export class UsersService {
  private readonly users: Prisma.UserDelegate<DefaultArgs>;

  constructor(private readonly databaseService: DatabaseService) {
    this.users = this.databaseService.user;
  }

  findOneByEmail(email: User['email']) {
    return this.users.findUnique({
      where: {
        email,
      },
    });
  }

  findOneById(userId: User['id']) {
    return this.users.findUnique({
      where: {
        id: userId,
      },
    });
  }

  create(data: Prisma.UserCreateArgs['data']) {
    return this.users.create({ data });
  }
}
