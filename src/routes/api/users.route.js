import express from 'express';
import users from '../../controllers/users.controller';
import checkForEmail from '../../validation/user.validation';
import validation from '../../validation/validation';
import catchErrors from '../../utils/helper';
import { decodeQueryToken } from '../../middlewares/checkToken';

const router = express.Router();

/**
 * @swagger
 *
 * /auth/signup:
 *   post:
 *     summary: User Signup
 *     description: Creates a new user account
 *     tags:
 *       - Users
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     produces:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *               message:
 *                 type: string
 *               data:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   firstName:
 *                     type: string
 *                   lastName:
 *                     type: string
 *                   token:
 *                     type: string
 *     responses:
 *       201:
 *         description: created
 */
router.post('/auth/signup', validation, checkForEmail, catchErrors(users.createUser));

/**
 * @swagger
 *
 * /auth/verification:
 *  get:
 *    tags:
 *      - users
 *    summary: User email verification
 *    description: verifies users acount using an email
 *    produces:
 *      application/json:
 *        schema:
 *          type: object
 *          properties:
 *            status:
 *              type: string
 *            message:
 *              type: string
 *    parameters:
 *      - in: query
 *        name: token
 *        description: user's token for verification
 *        type: string
 *    responses:
 *      '500':
 *        description: Error at verification
 *      '401':
 *        description: invalid token
 *      '409':
 *        description: trying to verify again
 *      '200':
 *        description: succesfull verified
 */
router.get('/auth/verification', decodeQueryToken, catchErrors(users.verifyAccount));

/**
 * @swagger
 *
 * /auth/signin:
 *   post:
 *     summary: User SignIn
 *     description: Logs in an existing User
 *     tags:
 *       - Users
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     produces:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *               message:
 *                 type: string
 *               data:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   firstName:
 *                     type: string
 *                   lastName:
 *                     type: string
 *                   token:
 *                     type: string
 *     responses:
 *       200:
 *         description: success
 */
router.post('/auth/signin', validation, catchErrors(users.findUser));

/**
 * @swagger
 *
 * /auth/reverifyUser:
 *  get:
 *    tags:
 *      - users
 *    summary: User email verification
 *    description: verifies users acount using an email
 *    produces:
 *      application/json:
 *        schema:
 *          type: object
 *          properties:
 *            status:
 *              type: string
 *            message:
 *              type: string
 *    parameters:
 *      - in: query
 *        name: email
 *        description: user's email
 *        type: string
 *    responses:
 *      '500':
 *        description: Error at verification
 *      '404':
 *        description: email not found
 *      '200':
 *        description: succesfull verified
 */
router.get('/auth/reverifyUser', catchErrors(users.resendEmail));

/**
 * @swagger
 *
 * /auth/forgotPassword:
 *  post:
 *    tags:
 *      - users
 *    summary: User forgot password link
 *    description: Enables the reset password to get the users email so as to reset
 *    produces:
 *      application/json:
 *        schema:
 *          type: object
 *          properties:
 *            status:
 *              type: string
 *            message:
 *              type: string
 *    requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *    parameters:
 *      - in: query
 *        name: token
 *        description: token from user email to reset
 *        type: string
 *    responses:
 *      '500':
 *        description: Error at forgot password
 *      '404':
 *        description: email not found
 *      '200':
 *        description: succesfull sent reset link
 */
router.post('/auth/forgotPassword', catchErrors(users.forgotPassword));

/**
 * @swagger
 *
 * /auth/forgotPassword:
 *  patch:
 *    tags:
 *      - users
 *    summary: User forgot password link
 *    description: Enables the reset password to get the users email so as to reset
 *    produces:
 *      application/json:
 *        schema:
 *          type: object
 *          properties:
 *            status:
 *              type: string
 *            message:
 *              type: string
*    parameters:
 *      - in: query
 *        name: token
 *        description: user's token for verification
 *        type: string
 *    requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *    responses:
 *      '500':
 *        description: Error at forgot password
 *      '404':
 *        description: email not found
 *      '200':
 *        description: succesfull sent reset link
 */
router.patch('/auth/resetPassword', validation, decodeQueryToken, catchErrors(users.resetPassword));

export default router;
