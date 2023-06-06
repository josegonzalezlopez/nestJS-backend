import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';

import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { JwtPayload } from './interfaces/jwt-payload.iterface';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  

constructor( @InjectModel( User.name )
              private userModel: Model<User>,
              private jwtService: JwtService) {}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const {password, ...userData} = createUserDto;

      const newUser = new this.userModel( {
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      await newUser.save();

      const { password: _, ...returnData} = newUser.toJSON();
      return returnData;
    } catch (error) {
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Uncontrolled error!!!')
    }

  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create( registerUserDto );

    return {
      user: user,
      token: this.getJwtToken({id: user._id})
    }
  }

  async login(loginDto: LoginDto){  

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email});
    console.log({ user });
    
    if( !user || !bcryptjs.compareSync(password, user.password) ){
      throw new UnauthorizedException('Not valid credentials');
    }

   const { password:_, ...userInfo} = user.toJSON();

    return {
      user: userInfo,
      token: this.getJwtToken({id: user.id})
    }
    
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(userId: string){
    const user = await this.userModel.findById( userId );
    const { password, ...userInfo } = user.toJSON();
    return userInfo;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ){
    const token = this.jwtService.sign( payload );
    return token;
  }
}
