import {Request, Response, NextFunction, response} from 'express';
import CustomError from '../../classes/CustomError';
import bcrypt from 'bcryptjs';
import userModel from '../models/userModel';
import {LoginUser, UserInput, UserOutput} from '../../types/DBTypes';
import {UserResponse} from '../../types/MessageTypes';
import Filter from 'bad-words';

const salt = bcrypt.genSaltSync(12);

const checkUsername = (user: UserInput) => {
  const usernamePattern = new RegExp('^[a-zA-Z0-9](_(?!(\.|_))|\.(?!(_|\.))|[a-zA-Z0-9]){3,18}[a-zA-Z0-9]$');
    
    if (!usernamePattern.test(user.user_name)) {
      new CustomError('Invalid username', 400);
      return false;
    }

    const filter = new Filter();

    if (filter.isProfane(user.user_name)) {
      new CustomError('Username contains naughty word', 400);
      return false;
    }
    return true;
}

const check = (req: Request, res: Response) => {
  console.log('check');
  res.json({message: 'I am alive'});
};

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    console.log('userListGet');
    const users = await userModel.find().select('-password -role');
    res.json(users);
  } catch (error) {
    next(error);
  }
};

const userGet = async (
  req: Request<{id: string}>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const user = await userModel
      .findById(req.params.id)
      .select('-password -role');
    if (!user) {
      next(new CustomError('User not found', 404));
    }
    res.json(user);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const verifyPassword = async (
  req: Request<{}, {}, {user_name: string, password: string}>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const {user_name, password} = req.body;
    const user = await userModel.findOne({user_name}).select("password");
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    if (await bcrypt.compare(password, user.password)) {
      res.json(true);
    } else {
      res.json(false);
    }
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
}

const userPost = async (
  req: Request<{}, {}, UserInput>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const user = req.body;

    if (!checkUsername(user)) {
      next(new CustomError('Invalid username', 400));
      return;
    }

    user.password = await bcrypt.hash(user.password, salt);
    const newUser = await userModel.create(user);
    const response: UserResponse = {
      message: 'user created',
      user: {
        user_name: newUser.user_name,
        id: newUser._id,
      },
    };
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const userPut = async (
  req: Request<{id?: string}, {}, UserInput>,
  res: Response<UserResponse, {userFromToken: LoginUser}>,
  next: NextFunction,
) => {
  try {
    const {userFromToken} = res.locals;
    if (checkUsername(req.body)) {
      return;
    }

    let id = userFromToken.id;
    if (userFromToken.role === 'admin' && req.params.id) {
      id = req.params.id;
    }
    console.log('id', id, req.body);
    const result = await userModel
      .findByIdAndUpdate(id, req.body, {
        new: true,
      })
      .select('-password -role');
    if (!result) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response: UserResponse = {
      message: 'user updated',
      user: {
        user_name: result.user_name,
        id: result._id,
      },
    };
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const userDelete = async (
  req: Request<{id?: string}>,
  res: Response<UserResponse, {userFromToken: LoginUser}>,
  next: NextFunction,
) => {
  try {
    const {userFromToken} = res.locals;
    let id;
    if (req.params.id && userFromToken.role === 'admin') {
      id = req.params.id;
      console.log('i am admin', id);
    }
    if (userFromToken.role === 'user') {
      id = userFromToken.id;
      console.log('i am user', id);
    }

    const result = await userModel
      .findByIdAndDelete(id)
      .select('-password -role');
    if (!result) {
      next(new CustomError('User not found', 404));
      return;
    }
    const response: UserResponse = {
      message: 'user deleted',
      user: {
        user_name: result.user_name,
        id: result._id,
      },
    };
    console.log('delete response', response);
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const checkToken = async (
  req: Request,
  res: Response<UserResponse, {userFromToken: LoginUser}>,
  next: NextFunction,
) => {
  try {
    const userData: UserOutput = await userModel
      .findById(res.locals.userFromToken.id)
      .select('-password, role');
    if (!userData) {
      next(new CustomError('Token not valid', 404));
      return;
    }
    const message: UserResponse = {
      message: 'Token valid',
      user: userData,
    };
    res.json(message);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {check, userListGet, userGet, verifyPassword, userPost, userPut, userDelete, checkToken};
