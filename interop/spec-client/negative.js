// Negative control: a client built from the specification must also understand relay
// REFUSALS. "Everything accepted" proves nothing when a relay accepts anything.
'use strict';

const a = require('./a4a.js');
const URL = process.argv[2] || 'ws://localhost:8080';
const now = () => Math.floor(Date.now() / 1000);

async function main() {
  const relay = new a.Relay(URL);
  await relay.connect();
  const owner = a.newKeys(), agent = a.newKeys();
  const expiry = now() + 30 * 86400;
  const results = [];
  const keys = [owner, agent];

  const check = async (label, ev, expectOk) => {
    const res = await relay.publish(ev);
    const good = res.ok === expectOk;
    results.push([label, good, res.reason]);
    console.log(`${good ? 'YES' : 'NO '}  ${label}${res.ok ? '' : ' — ' + res.reason}`);
  };

  // Section 1.2: a delegation without `d` may be stored, but agent events using it fail.
  const noD = a.signEvent({
    kind: 31000,
    tags: [['delegate', agent.pk], ['owner', owner.pk], ['expiration', String(expiry)]],
    content: 'mandate without d',
  }, owner);
  await check('delegation without `d` stored (section 1.2: refusal occurs later)', noD, true);

  const byNoD = a.intent(agent, noD.id, {
    type: 'service_request', category: 'development', need: 'landing_page',
    budgetMin: 0, budgetMax: 1, currency: 'USD', deadline: now() + 86400, text: '',
  });
  await check('agent event using delegation without `d` is REFUSED', byNoD, false);

  // Section 1.1 rule 7: a non-canonical number invalidates the entire event.
  const good = a.delegation(owner, agent.pk, 'ordinary', expiry);
  await check('CONTROL: valid delegation accepted', good, true);

  const badExp = a.signEvent({
    kind: 31002,
    tags: [['intent_type', 'service_request'], ['category', 'development'],
           ['need', 'x'], ['budget_min', '0'], ['budget_max', '1'],
           ['currency', 'USD'], ['deadline', String(now() + 86400)],
           ['delegation', good.id], ['expiration', '+' + (now() + 86400)],
           ['d', 'noncanonical-probe']],
    content: '',
  }, agent);
  await check('intent with `expiration` = "+N" is REFUSED (rule 7)', badExp, false);

  const okIntent = a.intent(agent, good.id, {
    type: 'service_request', category: 'development', need: 'landing_page',
    budgetMin: 0, budgetMax: 1, currency: 'USD', deadline: now() + 86400, text: '',
  });
  await check('CONTROL: intent with canonical numbers accepted', okIntent, true);

  // Section 1.1.1: a subscription with a wrong field type must receive CLOSED, not silence.
  try {
    await relay.query({ kinds: ['not a number'] });
    results.push(['REQ with malformed filter rejected through CLOSED', false, 'received EOSE']);
    console.log('NO   REQ with malformed filter rejected through CLOSED — received EOSE');
  } catch (e) {
    const good = /subscription rejected/.test(e.message);
    results.push(['REQ with malformed filter rejected through CLOSED', good, e.message]);
    console.log(`${good ? 'YES' : 'NO '}  REQ with malformed filter rejected through CLOSED ` +
                `(${e.message.slice(0, 60)})`);
  }

  // Clean up while keys are available; otherwise protected mandates become permanent.
  let removed = 0;
  for (const k of keys) {
    const mine = await relay.query({ authors: [k.pk], limit: 500 });
    const ids = mine.filter((e) => e.kind !== 5).map((e) => e.id);
    if (!ids.length) continue;
    const del = a.signEvent({ kind: 5, tags: ids.map((i) => ['e', i]), content: 'cleanup' }, k);
    const res = await relay.publish(del);
    if (res.ok) removed += ids.length;
  }
  console.log(`\ncleanup: removed ${removed} events`);

  const failed = results.filter(([, ok]) => !ok).length;
  console.log(`failed: ${failed} of ${results.length}`);
  relay.close();
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
