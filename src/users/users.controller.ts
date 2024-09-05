import { Controller, Get, Param, Patch, Req, Res, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/jwt.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  getMyUser(@Param() params: {id: string}, @Req() req) {
    return this.usersService.getMyUser(params.id, req);
  }

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  updateUser(@Param() params: {id: string}, @Req() req, @Res() res) {
    return this.usersService.updatePassword(params.id, req, res);
  }

  @Get()
  getUsers() {
    return this.usersService.getUsers();
  }
}
