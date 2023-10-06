import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { User } from '@prisma/client';
import * as argon2 from 'argon2';
import { UsersService } from '../users/users.service';
import type { AuthDto } from './dto';
import type { JwtPayload } from './types';
import { Cache } from 'cache-manager';
import { type CreateUserDto } from 'src/users/dto';
import envConfig from 'src/config/env.config';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    @Inject('CACHE_MANAGER') private readonly cacheManager: Cache,
    @Inject(envConfig.KEY) private env: ConfigType<typeof envConfig>,
  ) {}

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.usersService.findOneByEmail(email);

    if (user && (await argon2.verify(user.passwordHash, password))) {
      return user;
    }

    return null;
  }

  async loginLocal({ email, password }: AuthDto) {
    const user = await this.usersService.findOneByEmail(email);

    if (!user) throw new BadRequestException('Email/Password is incorrect');

    if (!(await argon2.verify(user.passwordHash, password)))
      throw new BadRequestException('Email/Password is incorrect');

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRefreshToken(
      user.id,
      await this.hashData(tokens.refreshToken),
    );

    return tokens;
  }

  async logout(userId: string) {
    if ((await this.cacheManager.get(userId)) == null) {
      throw new UnauthorizedException('User is not logged in');
    }

    return this.cacheManager.del(userId);
  }

  async registerLocal({ email, password, ...rest }: CreateUserDto) {
    const userExists = await this.usersService.findOneByEmail(email);

    if (userExists) {
      throw new BadRequestException('User already exists');
    }

    const newUser = await this.usersService.create({
      email,
      passwordHash: await this.hashData(password),
      ...rest,
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);

    await this.updateRefreshToken(
      newUser.id,
      await this.hashData(tokens.refreshToken),
    );

    return tokens;
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findOneById(userId);

    const cachedRefreshTokenHash = await this.cacheManager.get<string>(userId);

    if (!user || !cachedRefreshTokenHash)
      throw new ForbiddenException('Access Denied');

    if (!(await argon2.verify(cachedRefreshTokenHash, refreshToken)))
      throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRefreshToken(
      user.id,
      await this.hashData(tokens.refreshToken),
    );

    return tokens;
  }

  private hashData(data: string) {
    return argon2.hash(data);
  }

  private async updateRefreshToken(userId: string, refreshTokenHash: string) {
    return await this.cacheManager.set(
      userId,
      refreshTokenHash,
      7 * 24 * 60 * 60 * 1000, // 7 days
    );
  }

  private async getTokens(userId: string, email: string) {
    const newPayload: JwtPayload = {
      sub: userId,
      email,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(newPayload, {
        secret: this.env.JWT_ACCESS_SECRET,
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(newPayload, {
        secret: this.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
