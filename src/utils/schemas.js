import Joi from '@hapi/joi';

const signupSchema = {
  firstName: Joi.string().strict().trim().required(),
  lastName: Joi.string().strict().trim().required(),
  email: Joi.string().strict().trim().email()
    .required(),
  password: Joi.string().alphanum().min(8).required()
    .strict(),
};

const signinSchema = {
  email: Joi.string().strict().trim().email()
    .required(),
  password: Joi.required(),
};

export default {
  '/auth/signup': signupSchema,
  '/auth/signin': signinSchema
};
