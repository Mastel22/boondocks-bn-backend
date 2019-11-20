import express from 'express';
import { urlencoded, json } from 'body-parser';
import cors from 'cors';
import router from './routes/index';
import logger from './utils/winston';
import Responses from './utils/response';
import config from './config';
import ErrorHandler from './utils/error';

const isDevelopment = config.env;

const app = express();

const allowedOrigins = [
  // We shall remove this URL for production
  'http://localhost',
  // Our front end URL to be added here in phase 2 of SIMS
];
app.use(cors({
  origin(origin, callback) {
    // allow requests with no origin
    // (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not '
                + 'allow access from the specified Origin.';
      return callback(new Error(msg), false);
    } return callback(null, true);
  },
  // To enable HTTP cookies over CORS
  credentials: true,
}));

app.use(urlencoded({ extended: false }));
app.use(json());

// used in testing heroku
app.get('/', (req, res) => Responses.handleSuccess(200, 'Welcome to Barefoot Nomad', res));

app.use(router);
app.use((req, res) => Responses.handleError(404, 'Not found', res));

// development error handler middleware
app.use((err, req, res, next) => {
  if (isDevelopment !== 'development') {
    return next(err);
  }
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${
    req.ip
  } - Stack: ${err.stack}`);

  return Responses.handleError(err.statusCode, `${err.message} - check logs for more info`, res);
});

// Production and testing error handler middleware
app.use((err, req, res) => {
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${
    req.ip
  } - Stack: ${err.stack}`);

  return Responses.handleError(err.statusCode, err.message, res);
});

process.on('unhandledRejection', (reason) => {
  throw new ErrorHandler(reason);
});

process.on('uncaughtException', (error) => {
  logger.error(`Uncaught Exception: ${500} - ${error.message}, Stack: ${error.stack}`);
  process.kill(process.pid, 'SIGTERM');
});

export default app;