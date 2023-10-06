import { Controller, Get, NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserEntity } from './entities';
import { GetCurrentUser } from 'src/shared/decorators';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  async getMe(@GetCurrentUser('sub') userId: string) {
    const user = await this.usersService.findOneById(userId);

    if (!user) throw new NotFoundException('User not found');

    return new UserEntity(user);
  }
}
