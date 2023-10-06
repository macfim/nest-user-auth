import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import type { JwtPayload } from './types';
import { GetCurrentUser, Public } from 'src/shared/decorators';
import { CreateUserDto } from 'src/users/dto';
import { RefreshTokenGuard } from 'src/shared/guards';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('local/register')
  registerLocal(@Body() createUserDto: CreateUserDto) {
    return this.authService.registerLocal(createUserDto);
  }

  @Public()
  @Post('local/login')
  loginLocal(@Body() data: AuthDto) {
    return this.authService.loginLocal(data);
  }

  @Get('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@GetCurrentUser('sub') userId: string) {
    await this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  refreshTokens(@GetCurrentUser() user: JwtPayload & { refreshToken: string }) {
    return this.authService.refreshTokens(user.sub, user.refreshToken);
  }
}
