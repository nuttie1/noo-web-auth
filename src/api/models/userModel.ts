// mongoose schema for user
// intface User is located in src/interfaces/User.ts

import mongoose from 'mongoose';
import {User} from '../../types/DBTypes';

const userModel = new mongoose.Schema<User>({
  user_name: {
    type: String,
    required: true,
    unique: true,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  password: {
    type: String,
    required: true,
  },
  points: {
    type: Number,
    default: 0,
    required: false,
  },
});

// Duplicate the ID field.
userModel.virtual('id').get(function () {
  return this._id.toHexString();
});

// Ensure virtual fields are serialised.
userModel.set('toJSON', {
  virtuals: true,
});

export default mongoose.model<User>('User', userModel);
