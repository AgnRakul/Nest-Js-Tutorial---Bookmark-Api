import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signUp(dto: AuthDto) {
    // Generate Password
    const hash = await argon.hash(dto.password);
    // Save the New User in the db

    try {
      const user = this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete (await user).hash;

      // return the saved User

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'The Credentails are Already Taken Try Something New ! );',
          );
        }
      }
      throw error;
    }
  }

  async signIn(dto: AuthDto) {
    // Find the User by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      }
    });
    // if user does not exist throw error
    if (!user)
      throw new ForbiddenException(
        `The is No Record Found on Following Email: ${dto.email}`,
      );

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if password incorrect throw Error
    if (!pwMatches) throw new ForbiddenException('Credentials Incorrect');

    // send back the user
    delete user.hash;
    return user;

    return {
      Msg: 'I am Signed In Successfully',
    };
  }
}
