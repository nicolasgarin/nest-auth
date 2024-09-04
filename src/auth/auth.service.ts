import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;
    return {
      msg: 'signup successful',
    };
  }

  async signin() {
    return {
      msg: 'signin successful',
    };
  }

  async signout() {
    return {
      msg: 'signout successful',
    };
  }
}
