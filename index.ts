import { authenticate } from './src/authenticate';

export const handler = async (event: any) => {
  try {
    const data = await authenticate(event);
    return data;
  } catch (err) {
    throw Error('Unauthorized');
  }
};
