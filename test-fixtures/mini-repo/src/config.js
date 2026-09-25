// Fixture: hardcoded credentials, beside the way they should be read.
//
// The values are fake, and obviously so — but the detectors are about shape, not
// authenticity, and a check that only fired on real credentials would be a check
// that never fires in a test.
//
// The last one is safe: the assignment has no literal on the right-hand side.
// The rule that flags the three above would be worthless if it could not tell
// the difference, so the difference is here to be tested.
const config = {
  apiKey: "sk_live_9f8a7b6c5d4e3f2a1b0c",
  dbPassword: "Spr1ng2024!prod",
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  region: "eu-west-1",
  tokenTtlSeconds: 900,
};

module.exports = {
  ...config,
  sessionSecret: process.env.SESSION_SECRET,
};
