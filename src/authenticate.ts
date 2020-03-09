import dotenv from 'dotenv';
import * as jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import util from 'util';

import { generatePolicy } from './aws-policy-generator';
import { getToken } from './token';

dotenv.config();

const jwtOptions = {
  audience: process.env.AUDIENCE,
  issuer: process.env.TOKEN_ISSUER,
};

export const authenticate = async (params: any) => {
  const token = getToken(params);

  const decoded: any = jwt.decode(token, { complete: true });

  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error('invalid token');
  }

  const client = jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: `${process.env.JWKS_URI}`,
  });

  const getSigningKey = util.promisify(client.getSigningKey);

  const key = await getSigningKey(decoded.header.kid);
  const verified: any = jwt.verify(token, key.getPublicKey(), jwtOptions);

  return {
    principalId: verified.sub,
    policyDocument: generatePolicy('Allow', params.methodArn),
    context: { scope: verified.scope },
  };
};
