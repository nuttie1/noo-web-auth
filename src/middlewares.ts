/* eslint-disable @typescript-eslint/no-unused-vars */
import {NextFunction, Request, Response} from 'express';
import CustomError from './classes/CustomError';
import jwt from 'jsonwebtoken';
import userModel from './api/models/userModel';
import {ErrorResponse} from './types/MessageTypes';
import {LoginUser, TokenContent, UserOutput} from './types/DBTypes';

const notFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new CustomError(`🔍 - Not Found - ${req.originalUrl}`, 404);
  next(error);
};

const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response<ErrorResponse>,
  next: NextFunction,
) => {
  console.error('errorHandler', err);
  res.status(err.status || 500);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack,
  });
};

const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const bearer = req.headers.authorization;
    // console.log(bearer);
    if (!bearer) {
      next(new CustomError('No token provided', 401));
      return;
    }
    const token = bearer.split(' ')[1];
    if (!token || token === 'undefined') {
      next(new CustomError('No token provided', 401));
      return;
    }
    const userFromToken = jwt.verify(
      token,
      process.env.JWT_SECRET as string,
    ) as LoginUser;

    const user = await userModel.findById(userFromToken.id).select('-password');

    if (!user) {
      next(new CustomError('Token not valid', 404));
      return;
    }

    // possibly updated data from database
    const outputUser: LoginUser = {
      user_name: user.user_name,
      id: user.id,
      role: user.role,
    };

    res.locals.userFromToken = outputUser;
    next();
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {notFound, errorHandler, authenticate};
