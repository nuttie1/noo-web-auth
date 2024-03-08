import express from 'express';
import {
  check,
  checkToken,
  userDelete,
  userGet,
  verifyPassword,
  userListGet,
  userPost,
  userPut,
} from '../controllers/userController';
import {authenticate} from '../../middlewares';

const router = express.Router();

router
  .route('/')
  .get(userListGet)
  .post(userPost)
  .put(authenticate, userPut)
  .delete(authenticate, userDelete);

router.get('/token', authenticate, checkToken);

router.route('/check').get(check);

router
  .route('/:id')
  .get(userGet)
  .delete(authenticate, userDelete)
  .put(authenticate, userPut);

router 
  .route('/username/:user_name')
  .post(verifyPassword)

export default router;
