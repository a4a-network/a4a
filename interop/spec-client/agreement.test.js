'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const a = require('./a4a.js');

const vectors = JSON.parse(fs.readFileSync(
  path.join(__dirname, '../vectors/agreement-v2.json'), 'utf8',
));
const base = vectors.cases.find((v) => v.name === 'legacy-ascii').terms;
const compact = {
  intentId: 'i', offerId: 'o', price: '0', currency: '', deadline: '0', agentA: 'a', agentB: 'b',
};

test('agreement-v2 domain is unchanged', () => {
  assert.equal(a.AGREEMENT_TAG, 'a4a/agreement/v2');
  assert.equal(a.AGREEMENT_TAG, vectors.domain);
});

for (const vector of vectors.cases) {
  test(`fixed canonical UTF-8 bytes: ${vector.name}`, () => {
    const canonical = a.agreementCanonical(vector.terms);
    assert.equal(typeof canonical, 'string');
    assert.equal(canonical, vector.canonical);
    assert.deepEqual(Buffer.from(canonical, 'utf8'), Buffer.from(vector.canonical, 'utf8'));
    assert.ok([...Buffer.from(canonical, 'utf8')].every((byte) => byte < 128));
  });

  test(`fixed tagged digest: ${vector.name}`, () => {
    assert.equal(a.agreementDigest(vector.terms), vector.digest);
  });

  test(`exact BigInt inputs: ${vector.name}`, () => {
    const terms = { ...vector.terms, price: BigInt(vector.terms.price), deadline: BigInt(vector.terms.deadline) };
    assert.equal(a.agreementCanonical(terms), vector.canonical);
    assert.equal(a.agreementDigest(terms), vector.digest);
  });
}

test('legacy ASCII digest is unchanged for safe Number callers', () => {
  assert.equal(a.agreementDigest({ ...base, price: 45000, deadline: 1800000000 }),
    '0c3a734fd58e2f95ce39875702a748410de1ee67c3e267e623bc0448122526c8');
});

test('A4A eventId retains its existing JSON serialization', () => {
  const event = {
    pubkey: 'a'.repeat(64), created_at: 1800000000, kind: 31004,
    tags: [['currency', '\u20bd\ud83d\ude80'], ['deadline', '9999999999999999999']],
    content: 'e\u0301\n\u007f',
  };
  assert.equal(a.eventId(event), '043e42c372bcf1bd28b8d3d0e92963e79d282b263a2b037be56e0295507a74a1');
});

const acceptedIntegers = [
  ['zero string', '0', '0'], ['zero Number', 0, '0'], ['zero BigInt', 0n, '0'],
  ['one Number', 1, '1'],
  ['maximum safe Number', Number.MAX_SAFE_INTEGER, '9007199254740991'],
  ['first unsafe integer as string', '9007199254740992', '9007199254740992'],
  ['first unsafe integer as BigInt', 9007199254740992n, '9007199254740992'],
  ['unrepresentable integer as string', '9007199254740993', '9007199254740993'],
  ['unrepresentable integer as BigInt', 9007199254740993n, '9007199254740993'],
  ['maximum string', '9999999999999999999', '9999999999999999999'],
  ['maximum BigInt', 9999999999999999999n, '9999999999999999999'],
];

for (const [label, value, digits] of acceptedIntegers) {
  test(`uint and agreement accept ${label} exactly`, () => {
    assert.equal(a.uint(value, 'test'), digits);
    assert.equal(a.agreementCanonical({ ...compact, price: value, deadline: value }),
      `["a4a-agreement-v2","i","o","${digits}","",${digits},"a","b"]`);
    assert.equal(a.agreementDigest({ ...base, price: value, deadline: value }),
      a.agreementDigest({ ...base, price: digits, deadline: digits }));
  });
}

const invalidIntegers = [
  ['empty', ''], ['leading zero', '01'], ['double zero', '00'], ['plus', '+1'],
  ['negative string', '-1'], ['negative zero string', '-0'], ['decimal', '1.0'],
  ['exponent', '1e3'], ['hex', '0x10'], ['binary', '0b10'], ['separator', '1_000'],
  ['leading space', ' 1'], ['trailing space', '1 '], ['tab', '1\t'],
  ['LF', '1\n'], ['CR', '1\r'], ['CRLF', '1\r\n'],
  ['line separator', '1\u2028'], ['paragraph separator', '1\u2029'],
  ['NUL', '1\0'], ['non-ASCII digits', '\u0661'],
  ['above maximum string', '10000000000000000000'],
  ['above maximum BigInt', 10000000000000000000n], ['negative BigInt', -1n],
  ['negative Number', -1], ['negative zero', -0], ['fraction', 1.5],
  ['NaN', NaN], ['infinity', Infinity], ['negative infinity', -Infinity],
  ['first unsafe Number', Number.MAX_SAFE_INTEGER + 1],
  ['already rounded Number', Number('9007199254740993')],
  ['large integral Number', 1e18], ['above maximum Number', 1e19],
  ['true', true], ['false', false], ['null', null], ['undefined', undefined],
  ['symbol', Symbol('1')], ['object', {}], ['array', ['1']], ['empty array', []],
  ['boxed string', new String('1')], ['boxed number', new Number(1)],
  ['boxed BigInt', Object(1n)], ['function', () => '1'],
];

for (const [label, value] of invalidIntegers) {
  test(`uint rejects ${label}`, () => assert.throws(() => a.uint(value, 'test')));
  for (const field of ['price', 'deadline']) {
    test(`agreement rejects ${label} in ${field}`, () => {
      assert.throws(() => a.agreementCanonical({ ...base, [field]: value }));
      assert.throws(() => a.agreementDigest({ ...base, [field]: value }));
    });
  }
}

for (const field of ['intentId', 'offerId', 'currency', 'agentA', 'agentB']) {
  test(`${field} requires a primitive string`, () => {
    for (const value of [undefined, null, true, 1, 1n, Symbol('x'), [], {}, new String('x'), () => 'x']) {
      assert.throws(() => a.agreementCanonical({ ...base, [field]: value }));
      assert.throws(() => a.agreementDigest({ ...base, [field]: value }));
    }
  });

  test(`${field} uses exact escaping without normalization or trimming`, () => {
    const value = ' A/"\\\b\t\n\f\r\x00\x1f~\x7f\u00e9e\u0301\u2028\u2029\ud83d\ude80\ud800X\udc00\uffff ';
    const encoded = '" A/\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f~\\u007f\\u00e9e\\u0301\\u2028\\u2029\\ud83d\\ude80\\ud800X\\udc00\\uffff "';
    const fields = ['"a4a-agreement-v2"', '"i"', '"o"', '"0"', '""', '0', '"a"', '"b"'];
    const indices = { intentId: 1, offerId: 2, currency: 4, agentA: 6, agentB: 7 };
    fields[indices[field]] = encoded;
    assert.equal(a.agreementCanonical({ ...compact, [field]: value }), `[${fields.join(',')}]`);
  });
}

test('caller objects are rejected without invoking coercion hooks', () => {
  let calls = 0;
  const object = {
    toString() { calls++; return '1'; },
    valueOf() { calls++; return 1; },
    toJSON() { calls++; return '1'; },
    [Symbol.toPrimitive]() { calls++; return '1'; },
  };
  assert.throws(() => a.uint(object, 'test'));
  for (const field of Object.keys(base)) {
    assert.throws(() => a.agreementCanonical({ ...base, [field]: object }));
    assert.throws(() => a.agreementDigest({ ...base, [field]: object }));
  }
  assert.equal(calls, 0);
});

test('all control characters use the specified escapes', () => {
  const currency = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join('');
  const escaped = '\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007'
    + '\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013'
    + '\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f';
  assert.equal(a.agreementCanonical({ ...compact, currency }),
    `["a4a-agreement-v2","i","o","0","${escaped}",0,"a","b"]`);
});

test('every non-ASCII UTF-16 code unit is escaped with lowercase hex', () => {
  for (let code = 0x7f; code <= 0xffff; code++) {
    assert.equal(a.agreementCanonical({ ...compact, currency: String.fromCharCode(code) }),
      `["a4a-agreement-v2","i","o","0","\\u${code.toString(16).padStart(4, '0')}",0,"a","b"]`);
  }
});

test('serialization neither validates identifiers nor changes input terms', () => {
  const terms = Object.freeze({ ...compact, intentId: '', offerId: 'not-an-id' });
  assert.equal(a.agreementCanonical(terms),
    '["a4a-agreement-v2","","not-an-id","0","",0,"a","b"]');
  assert.doesNotThrow(() => a.agreementDigest(terms));
  assert.deepEqual(terms, { ...compact, intentId: '', offerId: 'not-an-id' });
});

// Run only with fake dependencies: no sockets, key-file writes or real publishing.
async function counterpartTerms(cosign, digits) {
  const captured = {};
  const half = { tags: [
    ['intent', base.intentId], ['offer', base.offerId], ['price', digits, 'USD'],
    ['deadline', digits], ['agent_a', base.agentA], ['agent_b', base.agentB],
    ['sig_a', 'existing-signature'], ['sig_b', ''], ['delegation_a', 'da'], ['delegation_b', 'db'],
  ] };
  const fakeA = {
    tagValue: a.tagValue, tagFull: a.tagFull, pubkeyOf: () => base.agentB,
    Relay: class {
      async connect() {}
      async query() { return [half]; }
      async publish(ev) { captured.published = ev; return { ok: true }; }
      close() { captured.closed = true; }
    },
    offer(keys, delegation, terms) { captured.offer = terms; return { id: 'offer' }; },
    agreementDigest(terms) { captured.digest = terms; return 'digest'; },
    verifyDigest: () => true,
    signDigest: () => 'signature',
    agreement(keys, delegation, terms) { captured.agreement = terms; return { id: 'agreement' }; },
  };
  const fakeFs = {
    existsSync: () => true,
    readFileSync: () => JSON.stringify({ owner: '01', agent: '02', delegation: 'db' }),
    writeFileSync() { assert.fail('unexpected key-file write'); },
  };
  const source = fs.readFileSync(path.join(__dirname, 'counterpart.js'), 'utf8');
  await vm.runInNewContext(source, {
    require(name) {
      if (name === 'fs') return fakeFs;
      if (name === 'path') return path;
      if (name === './a4a.js') return fakeA;
      assert.fail(`unexpected dependency: ${name}`);
    },
    __dirname, Buffer,
    process: {
      argv: ['node', 'counterpart.js', 'ws://offline.invalid', base.intentId, ...(cosign ? ['--cosign'] : [])],
      exit(code) { assert.fail(`unexpected exit: ${code}`); },
    },
    console: { log() {}, error() {} },
  }, { filename: 'counterpart.js' });
  assert.ok(captured.closed);
  assert.ok(captured.published);
  return captured;
}

for (const digits of ['9007199254740993', '9999999999999999999', '01', '1e3']) {
  test(`counterpart forwards offer deadline tag unchanged: ${digits}`, async () => {
    const captured = await counterpartTerms(false, digits);
    assert.equal(captured.offer.eta, digits);
  });
  test(`counterpart forwards cosign numeric tags unchanged: ${digits}`, async () => {
    const captured = await counterpartTerms(true, digits);
    assert.equal(captured.digest.price, digits);
    assert.equal(captured.digest.deadline, digits);
    assert.equal(captured.agreement.price, digits);
    assert.equal(captured.agreement.deadline, digits);
  });
}
