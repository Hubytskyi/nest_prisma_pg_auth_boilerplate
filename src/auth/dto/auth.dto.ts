import { UserRole } from '@prisma/client';
import { IsEmail, IsNotEmpty, IsString, Matches } from 'class-validator';

export class Credentials {
  @IsEmail()
  email: string;

  /* Minimum eight characters, at least one lowercase letter, at least one uppercase letter, one number, special chars allowed */
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$&+,:;=?@#|'<>.^*()%!-]{8,}$/,
    { message: 'invalid password' },
  )
  password: string;
}

export class LoginDto extends Credentials {}

export class SignUpDto extends Credentials {
  @IsNotEmpty()
  @IsString()
  role: UserRole;
}
