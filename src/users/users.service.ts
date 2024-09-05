import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { Request, Response } from 'express';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';


@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMyUser(id: string, req: Request) {
    const decodedUser = req.user as { userId: string, email: string };

    const foundUser =  await this.prisma.user.findUnique({
      where: {
        id,
      },
    });

    if (!foundUser) {
      throw new NotFoundException();
    }

    if (foundUser.id !== decodedUser.userId) {
      throw new ForbiddenException();
    }

    delete foundUser.hashedPassword;

    return foundUser;
  }

  async updatePassword(id: string, req: Request, res: Response) {
    const decodedUser = req.user as { userId: string, email: string };
    const foundUser =  await this.prisma.user.findUnique({
      where: {
        id,
      },
    });

    if (!foundUser) {
      throw new NotFoundException('User not found');
    }

    if (foundUser.id !== decodedUser.userId) {
      throw new ForbiddenException();
    }

    await this.prisma.user.update({
      where: {
        id,
      },
      data: {
        hashedPassword: await this.hashPassword(req.body.password),
      },
    });

    return res.send({ msg: 'password updated' });
  }

  async getUsers() {
    return await this.prisma.user.findMany({
      select: { id: true, email: true },
    });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }
}
