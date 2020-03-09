export const generatePolicy = (effect: string, resource: string) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: resource,
    },
  ],
});
