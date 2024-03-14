/* eslint-disable @typescript-eslint/no-unused-vars */
import {NextFunction, Request, Response} from 'express';
import CustomError from './classes/CustomError';
import jwt from 'jsonwebtoken';
import userModel from './api/models/userModel';
import {ErrorResponse} from './types/MessageTypes';
import {LoginUser, TokenContent, UserOutput} from './types/DBTypes';

/**
 * Middleware to handle 404 errors
 * @param req - Request object. 
 * @param res  - Response object.
 * @param next - Next function. Will pass error to error handler
 */
const notFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new CustomError(`🔍 - Not Found - ${req.originalUrl}`, 404);
  next(error);
};

/**
 * Middleware to handle errors
 * @param err - Error object
 * @param req - Request object
 * @param res - Response object. Will contain error message and stack trace
 * @param next - Next function. Will pass error to error handler
 */
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

/**
 * Middleware to authenticate user
 * @param req - Request object. Should contain token in headers
 * @param res - Response object. Will contain user info
 * @param next - Next function. Will pass error to error handler
 * @returns - JSON object with user info
 */
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
      points : user.points
    };

    res.locals.userFromToken = outputUser;
    next();
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {notFound, errorHandler, authenticate};
