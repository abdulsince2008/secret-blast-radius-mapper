// Frontend configuration
const config = {
  apiUrl: process.env.REACT_APP_API_URL || 'https://api.example.com',
  awsAccessKeyId: process.env.REACT_APP_AWS_ACCESS_KEY_ID || 'AKIAIOSFODNN7EXAMPLE',
  stripeSecretKey: process.env.REACT_APP_STRIPE_SECRET_KEY || 'sk_test_abcdefghijklmnopqrstuvwx',
  sentryDsn: process.env.REACT_APP_SENTRY_DSN || 'https://abcdefghijklmnopqrstuvwx@sentry.io/123456',
};

export default config;