import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (foundUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return {
      msg: 'signup was successful',
    };
  }

  async signin(dto: AuthDto) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!foundUser) {
      throw new BadRequestException('Wrong credentials');
    }

    const isMatch = await this.comparePasswords(password, foundUser.hashedPassword);

    if (!isMatch) {
      throw new BadRequestException('Wrong credentials');
    }

    //sign jwt and return to the user

    return {
      msg: 'signin successful',
    };
  }

  async signout() {
    return {
      msg: 'signout successful',
    };
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePasswords(password: string, hashedPassword: string) {
    return await bcrypt.compare(password, hashedPassword);
  }
}
