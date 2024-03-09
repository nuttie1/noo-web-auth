import {Request, Response, NextFunction} from 'express';
import jwt from 'jsonwebtoken';
import CustomError from '../../classes/CustomError';
import userModel from '../models/userModel';
import bcrypt from 'bcryptjs';
import {LoginResponse} from '../../types/MessageTypes';
import {LoginUser} from '../../types/DBTypes';

const login = async (req: Request, res: Response, next: NextFunction) => {
  const {user_name, password} = req.body;

  console.log('user, password', user_name, password);
  const user = await userModel.findOne({user_name: user_name});

  if (!user) {
    next(new CustomError('Invalid username/password', 403));
    return;
  }

  if (!bcrypt.compareSync(password, user.password)) {
    next(new CustomError('Invalid username/password', 403));
    return;
  }

  const tokenContent: LoginUser = {
    user_name: user.user_name,
    id: user._id,
    role: user.role,
    points: user.points,
  };

  const token = jwt.sign(tokenContent, process.env.JWT_SECRET as string);
  const message: LoginResponse = {
    token,
    message: 'Login successful',
    user: {
      user_name: user.user_name,
      id: user._id,
      points: user.points
    },
  };
  return res.json(message);
};

export {login};
