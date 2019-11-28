import Joi from '@hapi/joi';

const signupSchema = Joi.object().keys({
  firstName: Joi.string().strict().trim().required(),
  lastName: Joi.string().strict().trim().required(),
  email: Joi.string().strict().trim().email()
    .required(),
  password: Joi.string().alphanum().min(8).required()
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

const signinSchema = Joi.object().keys({
  email: Joi.string().strict().trim().email()
    .required(),
  password: Joi.required()
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

const resetPassword = Joi.object().keys({
  password: Joi.string().alphanum().min(8).required()
    .strict()
});

const oneWaySchema = Joi.object().keys({
  hotelId: Joi.required(),
  type: Joi.string().strict().trim().required(),
  leavingFrom: Joi.string().strict().trim().required(),
  goingTo: Joi.string().strict().required(),
  travelDate: Joi.date().required(),
  reason: Joi.string().strict().required(),
  rooms: Joi.required()
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

const updateUserInfoSchema = Joi.object().keys({
  firstName: Joi.string().strict().trim(),
  lastName: Joi.string().strict().trim(),
  email: Joi.string().strict().trim().email(),
  password: Joi.string().alphanum().min(8).strict(),
  birthDate: Joi.date().iso().min('1950-01-01T00:00:00.000Z').max('2010-12-31T00:00:00.000Z'),
  preferredLanguage: Joi.string().strict().trim(),
  preferredCurrency: Joi.string().strict().trim(),
  residenceAddress: Joi.string().strict().trim(),
  gender: Joi.string().strict().trim(),
  department: Joi.string().strict().trim(),
  lineManager: Joi.string().strict().trim(),
  phoneNumber: Joi.string().regex(/^(\(\d{3}\) |\d{3}-)\d{3}-\d{4}$/).default('000-000-0000'),
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

const twoWaySchema = Joi.object().keys({
  hotelId: Joi.required(),
  type: Joi.string().strict().trim().required(),
  leavingFrom: Joi.string().strict().trim().required(),
  goingTo: Joi.string().strict().required(),
  travelDate: Joi.date().required(),
  returnDate: Joi.date().required(),
  reason: Joi.string().strict().required(),
  rooms: Joi.required()
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

const roleSchema = Joi.object().keys({
  email: Joi.string().strict().trim().email()
    .required(),
  role: Joi.string().strict().trim().valid(
    'super_administrator',
    'travel_administrator',
    'travel_team_member',
    'manager',
    'requester'
  )
    .required(),
}).options({
  abortEarly: false,
  language: {
    key: '{{key}} '
  }
});

export default {
  '/auth/resetPassword': resetPassword,
  '/auth/signup': signupSchema,
  '/auth/signin': signinSchema,
  '/trips/oneway': oneWaySchema,
  '/user/update-profile': updateUserInfoSchema,
  '/trips/return': twoWaySchema,
  '/auth/user/role': roleSchema
};
