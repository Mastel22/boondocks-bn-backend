import messenger from '../services/sms.service';
import twoFA from '../services/2fa-totp.service';
import Responses from '../utils/response';
import db from '../models';

const { handleSuccess, handleError } = Responses;
const { setupSecret, get, remove, verify, generate } = twoFA;

const totpSetup = async (req, res) => {
  const data = await setupSecret(res.locals.user.email, req.body.twoFAType);
  const { token } = generate(data.twoFASecret);

  if (req.body.twoFAType === 'sms_text_temp') {
    if (!data.phoneNumber) {
      return handleError(
        206,
        'You need to set a phoneNumber to activate 2FA with SMS.',
        res,
      );
    }
    await messenger(data.phoneNumber, `Your 6 Digit 60 seconds expiration PassCode is: ${token}`);
  }

  return handleSuccess(200, 'TOTP Secret created', res, data);
};

const totpGet = async (req, res) => handleSuccess(
  200,
  'TOTP Secret retrieved',
  res,
  await get(res.locals.user.email)
);

const totpDisable = async (req, res) => handleSuccess(
  200,
  'TOTP Secret removed',
  res,
  await remove(res.locals.user.email)
);

const totpVerify = async (req, res) => {
  const { type, secret, phoneNumber, dataURL } = res.locals.user.twoFA;
  if (type === 'none') {
    return handleError(400, 'User doesn\'t have 2FA enabled.', res);
  }

  const isTokenValid = verify({
    secret,
    token: req.body.token,
  });

  const tokenMethod = type.includes('sms_text') ? { phoneNumber } : { twoFADataURL: dataURL };

  const data = { twoFAType: type, twoFASecret: secret, ...tokenMethod };

  if (!isTokenValid) {
    return handleSuccess(400, 'Invalid TOTP token', res, { ...data, isTokenValid });
  }

  if (type.includes('_temp')) {
    await db.user.update({ twoFAType: type.split('_temp')[0] }, { where: { email: res.locals.user.email } });
  }

  return handleSuccess(200, 'Valid TOTP token', res, { ...data,
    isTokenValid,
  });
};

const totpSendTokenText = async (req, res) => {
  const { secret, phoneNumber } = req.body;
  const { token } = generate(secret);

  await messenger(phoneNumber, `Your 6 Digit 60 seconds expiration PassCode is: ${token}`);

  return handleSuccess(200, 'TOTP token sent', res, {
    twoFAType: 'sms_text',
    twoFASecret: secret,
    phoneNumber,
    tokenData: {
      token,
      message: `Your 6 Digit 60 seconds expiration PassCode is: ${token}`,
    },
  });
};

export default {
  totpSetup,
  totpGet,
  totpDisable,
  totpVerify,
  totpSendTokenText,
};
