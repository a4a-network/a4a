// Offline cross-language fixture bridge. Keys below are public test constants.
'use strict';
require('node:net').Socket.prototype.connect = function () {
  throw new Error('signature interoperability check forbids network');
};
const fs = require('node:fs');
const a = require('./spec-client/a4a.js');
const secret = '02'.repeat(32);
const keys = { sk: Uint8Array.from(Buffer.from(secret, 'hex')), pk: a.pubkeyOf(secret) };
const requests = JSON.parse(fs.readFileSync(0, 'utf8'));
const result = requests.map(({ terms, pythonSignature }) => {
  const digest = a.agreementDigest(terms);
  if (!a.verifyDigest(pythonSignature, digest, terms.agentA)) {
    throw new Error('Python signature did not verify against independently computed JS digest');
  }
  const changed = a.agreementDigest({ ...terms, currency: terms.currency + '!' });
  if (a.verifyDigest(pythonSignature, changed, terms.agentA)) {
    throw new Error('changed terms accepted the original signature');
  }
  return { digest, signature: a.signDigest(digest, keys), pubkey: keys.pk };
});
process.stdout.write(JSON.stringify(result));
