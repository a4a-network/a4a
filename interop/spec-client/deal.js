// End-to-end independent-client flow: delegations → intent → offer → agreement with
// TWO signatures. Everything is derived from the specification; each unanswered point
// is marked ASSUMPTION.
'use strict';

const a = require('./a4a.js');

const URL = process.argv[2] || 'ws://localhost:8080';
const now = () => Math.floor(Date.now() / 1000);
const guesses = [];
const guess = (what) => { guesses.push(what); console.log(`  ASSUMPTION: ${what}`); };

async function main() {
  const relay = new a.Relay(URL);
  await relay.connect();
  console.log(`relay: ${URL}\n`);

  // --- 0. Keys and mandates ------------------------------------------------------------
  const ownerA = a.newKeys(), agentA = a.newKeys();
  const ownerB = a.newKeys(), agentB = a.newKeys();
  const expiry = now() + 30 * 86400;

  const delegA = a.delegation(ownerA, agentA.pk, 'Customer agent', expiry);
  const delegB = a.delegation(ownerB, agentB.pk, 'Worker agent', expiry);
  for (const [ev, who] of [[delegA, 'customer'], [delegB, 'worker']]) {
    const res = await relay.publish(ev);
    console.log(`${who} mandate: ${res.ok ? 'accepted' : 'REFUSED — ' + res.reason}`);
    if (!res.ok) process.exit(1);
  }

  // --- 1. Customer intent --------------------------------------------------------------
  const deadline = now() + 5 * 86400;
  const intentEv = a.intent(agentA, delegA.id, {
    type: 'service_request', category: 'development', need: 'landing_page',
    budgetMin: 30000, budgetMax: 50000, currency: 'USD', deadline,
    text: 'Need a responsive five-section landing page.',
  });
  let res = await relay.publish(intentEv);
  console.log(`intent: ${res.ok ? 'accepted' : 'REFUSED — ' + res.reason}`);
  if (!res.ok) process.exit(1);

  // --- 2. Worker discovers the intent and responds ------------------------------------
  const found = await relay.query({ kinds: [31002], '#t': [`a4a:cat:development`], limit: 20 });
  const mine = found.filter((e) => e.id === intentEv.id);
  console.log(`worker found ${found.length} intents (target present: ${mine.length === 1})`);

  const offerEv = a.offer(agentB, delegB.id, {
    intentId: intentEv.id, price: 45000, currency: 'USD', eta: deadline,
    text: 'Ready to deliver in five days.',
  });
  res = await relay.publish(offerEv);
  console.log(`offer: ${res.ok ? 'accepted' : 'REFUSED — ' + res.reason}`);
  if (!res.ok) process.exit(1);

  // --- 3. Customer creates a half-signed agreement ------------------------------------
  const offers = await relay.query({ kinds: [31003], '#e': [intentEv.id], limit: 20 });
  const chosen = offers[0];
  console.log(`customer sees ${offers.length} offers`);

  // ASSUMPTION 1: currency comes from the THIRD element of the offer's `price` tag.
  // The intent has a separate `["currency","USD"]` tag, while offer and agreement
  // carry currency only inside `["price","45000","USD"]`. The specification does not
  // explain this distinction even though currency is a separate digest field.
  const priceTag = a.tagFull(chosen, 'price');
  const price = priceTag[1];
  const currency = priceTag[2];
  guess('agreement currency comes from the third element of the offer `price` tag');

  // ASSUMPTION 2: agreement deadline. The digest includes `deadline`, but the offer
  // calls its field `eta` and the intent uses `deadline`; the specification does not
  // identify which becomes the AGREEMENT deadline. Use the offer `eta`, which is the
  // worker's commitment rather than the customer's request.
  const agreedDeadline = a.tagValue(chosen, 'eta');
  guess('agreement deadline comes from offer `eta`, not intent `deadline`');

  // ASSUMPTION 3: which party is `agent_a`. Section 1.1 rule 5 only says "first named
  // in the event." Treat the customer as the initiator.
  const agentAPk = agentA.pk, agentBPk = agentB.pk;
  guess('`agent_a` is the initiator (customer); the publisher chooses the order');

  const digest = a.agreementDigest({
    intentId: intentEv.id, offerId: chosen.id, price, currency,
    deadline: agreedDeadline, agentA: agentAPk, agentB: agentBPk,
  });
  console.log(`terms digest: ${digest.slice(0, 16)}…`);

  const halfEv = a.agreement(agentA, delegA.id, {
    intentId: intentEv.id, offerId: chosen.id, price, currency, deadline: agreedDeadline,
    agentA: agentAPk, agentB: agentBPk,
    sigA: a.signDigest(digest, agentA), sigB: '',
    delegationA: delegA.id,
    // The counterparty mandate comes from its offer's `delegation` tag. v0.4 section
    // 1.2 says it appears in a half-signed event when the initiator knows the mandate.
    delegationB: a.tagValue(chosen, 'delegation'),
  });
  res = await relay.publish(halfEv);
  console.log(`agreement (one signature): ${res.ok ? 'accepted' : 'REFUSED — ' + res.reason}`);
  if (!res.ok) process.exit(1);

  // --- 4. Worker finds the agreement by `p`, verifies it, and countersigns ------------
  const forMe = await relay.query({ kinds: [31004], '#p': [agentB.pk], limit: 20 });
  const half = forMe.find((e) => a.tagValue(e, 'sig_b') === '' && a.tagValue(e, 'offer') === chosen.id);
  console.log(`worker found ${forMe.length} addressed agreements; ` +
              `${half ? 1 : 0} await its signature`);
  if (!half) process.exit(1);

  // Recompute the digest from terms rather than accepting a supplied value (section 1.1).
  const hp = a.tagFull(half, 'price');
  const myDigest = a.agreementDigest({
    intentId: a.tagValue(half, 'intent'), offerId: a.tagValue(half, 'offer'),
    price: hp[1], currency: hp[2], deadline: a.tagValue(half, 'deadline'),
    agentA: a.tagValue(half, 'agent_a'), agentB: a.tagValue(half, 'agent_b'),
  });
  const sigAok = a.verifyDigest(a.tagValue(half, 'sig_a'), myDigest, a.tagValue(half, 'agent_a'));
  console.log(`worker digest matches: ${myDigest === digest}`);
  console.log(`customer signature verified: ${sigAok}`);
  if (!sigAok) process.exit(1);

  const fullEv = a.agreement(agentB, delegB.id, {
    intentId: a.tagValue(half, 'intent'), offerId: a.tagValue(half, 'offer'),
    price: hp[1], currency: hp[2], deadline: a.tagValue(half, 'deadline'),
    agentA: a.tagValue(half, 'agent_a'), agentB: a.tagValue(half, 'agent_b'),
    sigA: a.tagValue(half, 'sig_a'), sigB: a.signDigest(myDigest, agentB),
    delegationA: a.tagValue(half, 'delegation_a'), delegationB: delegB.id,
  });
  res = await relay.publish(fullEv);
  console.log(`agreement (both signatures): ${res.ok ? 'accepted' : 'REFUSED — ' + res.reason}`);
  if (!res.ok) process.exit(1);

  // --- 5. Customer verifies that the agreement is concluded ---------------------------
  const back = await relay.query({ kinds: [31004], '#p': [agentA.pk], limit: 20 });
  const done = back.filter((e) => a.tagValue(e, 'sig_a') && a.tagValue(e, 'sig_b'));
  console.log(`\ncustomer sees ${back.length} agreements; ${done.length} have both signatures`);
  const d = done[0];
  const dp = a.tagFull(d, 'price');
  const finalDigest = a.agreementDigest({
    intentId: a.tagValue(d, 'intent'), offerId: a.tagValue(d, 'offer'),
    price: dp[1], currency: dp[2], deadline: a.tagValue(d, 'deadline'),
    agentA: a.tagValue(d, 'agent_a'), agentB: a.tagValue(d, 'agent_b'),
  });
  const okA = a.verifyDigest(a.tagValue(d, 'sig_a'), finalDigest, a.tagValue(d, 'agent_a'));
  const okB = a.verifyDigest(a.tagValue(d, 'sig_b'), finalDigest, a.tagValue(d, 'agent_b'));
  console.log(`both signatures verify over one digest: ${okA && okB}`);
  console.log(`concluded event ID differs from half-signed event: ${d.id !== half.id}`);

  // Clean up. This client reproduced finding 119 on its first run: keys existed only
  // in memory while mandates were protected from expiration deletion, leaving agents
  // on the test network that nobody could remove. The onboarding trap was exactly as
  // easy to trigger as the review report warned.
  let removed = 0;
  for (const k of [ownerA, agentA, ownerB, agentB]) {
    const mine = await relay.query({ authors: [k.pk], limit: 500 });
    const ids = mine.filter((e) => e.kind !== 5).map((e) => e.id);
    if (!ids.length) continue;
    const del = a.signEvent({ kind: 5, tags: ids.map((i) => ['e', i]), content: 'cleanup' }, k);
    if ((await relay.publish(del)).ok) removed += ids.length;
  }
  console.log(`cleanup: removed ${removed} events`);

  console.log(`\nassumptions in this run: ${guesses.length}`);
  relay.close();
  process.exit(okA && okB ? 0 : 1);
}

main().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
