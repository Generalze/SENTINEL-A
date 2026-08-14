import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { CLASSIFICATION_LEVELS } from '../classification';
import type { RequestWithPrincipal } from '../http-types';
import { requirePrincipal } from '../principal';
import { RequiresAction } from '../requires-action.decorator';
import { parseOrThrow } from '../validate';
import { CreateUserSchema, toUserResponse, type UserResponse } from './user.dto';
import { UsersService } from './users.service';

@Controller('api/v1/users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Post()
  @RequiresAction('user.admin')
  async create(@Req() request: RequestWithPrincipal, @Body() body: unknown): Promise<UserResponse> {
    const principal = requirePrincipal(request);
    const dto = parseOrThrow(CreateUserSchema, body);
    const user = await this.users.create(principal, dto);
    return toUserResponse(user);
  }

  /**
   * User records carry private contact information, which §47 classifies
   * SENSITIVE — this route requires an `x-purpose` header (§62.1's
   * purpose conjunct) in addition to the `user.admin` action.
   */
  @Get()
  @RequiresAction('user.admin', { classification: CLASSIFICATION_LEVELS.SENSITIVE })
  async list(@Req() request: RequestWithPrincipal): Promise<UserResponse[]> {
    const principal = requirePrincipal(request);
    const users = await this.users.listForOrganisation(principal);
    return users.map(toUserResponse);
  }
}
