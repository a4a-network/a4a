// Specification-based counterparty: responds to ANOTHER AGENT'S intent and completes
// the agreement.
//
// Unlike `deal.js`, where both parties are ours, the other party here is an MCP service
// in a container that this code knows nothing about. This mirrors an integrator's path:
// their agent uses MCP and encounters an independent implementation on the network.
//
//   node counterpart.js ws://localhost:8080 <intent_id>            # publish an offer
//   node counterpart.js ws://localhost:8080 <intent_id> --cosign   # countersign
//
// Keys are stored in adjacent `counterpart-keys.json`. The counterparty address must
// survive a restart or the second command will come from a different agent.
'use strict';

const fs = require('fs');
const path = require('path');
const a = require('./a4a.js');

const URL = process.argv[2] || 'ws://localhost:8080';
const INTENT = process.argv[3];
const COSIGN = process.argv.includes('--cosign');
const KEYFILE = path.join(__dirname, 'counterpart-keys.json');
const now = () => Math.floor(Date.now() / 1000);

function keys() {
  if (fs.existsSync(KEYFILE)) {
    const d = JSON.parse(fs.readFileSync(KEYFILE, 'utf8'));
    const restore = (hex) => ({ sk: Buffer.from(hex, 'hex'), pk: a.pubkeyOf(hex) });
    return { owner: restore(d.owner), agent: restore(d.agent), delegation: d.delegation };
  }
  const owner = a.newKeys(), agent = a.newKeys();
  return { owner, agent, delegation: null, fresh: true };
}

function save(k, delegationId) {
  fs.writeFileSync(KEYFILE, JSON.stringify({
    owner: Buffer.from(k.owner.sk).toString('hex'),
    agent: Buffer.from(k.agent.sk).toString('hex'),
    delegation: delegationId,
  }));
}

async function main() {
  if (!INTENT) { console.error('intent ID is required'); process.exit(2); }
  const relay = new a.Relay(URL);
  await relay.connect();
  const k = keys();

  let delegationId = k.delegation;
  if (!delegationId) {
    const d = a.delegation(k.owner, k.agent.pk, 'Specification counterparty', now() + 30 * 86400);
    const res = await relay.publish(d);
    if (!res.ok) { console.error('mandate rejected:', res.reason); process.exit(1); }
    delegationId = d.id;
    save(k, delegationId);
  }
  console.log(`agent: ${k.agent.pk}`);

  if (!COSIGN) {
    // The intent comes from the network; we never see the publisher's source code.
    const found = await relay.query({ ids: [INTENT] });
    if (!found.length) { console.error('intent is absent from the relay'); process.exit(1); }
    const it = found[0];
    console.log(`intent found: need ${JSON.stringify(a.tagValue(it, 'need'))}, ` +
                `budget up to ${a.tagValue(it, 'budget_max')}, description ` +
                `${it.content ? JSON.stringify(it.content) : 'ABSENT (strict mode)'}`);
    const ev = a.offer(k.agent, delegationId, {
      intentId: INTENT, price: 45000, currency: 'USD',
      eta: a.tagValue(it, 'deadline'),
    });
    const res = await relay.publish(ev);
    if (!res.ok) { console.error('offer rejected:', res.reason); process.exit(1); }
    console.log(`offer: ${ev.id}`);
    relay.close();
    return;
  }

  // --- Countersign ---------------------------------------------------------------------
  const mine = await relay.query({ kinds: [31004], '#p': [k.agent.pk], limit: 20 });
  const half = mine.find((e) => a.tagValue(e, 'sig_b') === '' || a.tagValue(e, 'sig_a') === '');
  if (!half) { console.error('no half-signed agreement addressed to this agent'); process.exit(1); }

  const empty = a.tagValue(half, 'sig_a') === '' ? 'a' : 'b';
  const price = a.tagFull(half, 'price');
  const digest = a.agreementDigest({
    intentId: a.tagValue(half, 'intent'), offerId: a.tagValue(half, 'offer'),
    price: price[1], currency: price[2], deadline: a.tagValue(half, 'deadline'),
    agentA: a.tagValue(half, 'agent_a'), agentB: a.tagValue(half, 'agent_b'),
  });
  const theirSlot = empty === 'a' ? 'sig_b' : 'sig_a';
  const theirKey = empty === 'a' ? 'agent_b' : 'agent_a';
  const theirOk = a.verifyDigest(a.tagValue(half, theirSlot), digest, a.tagValue(half, theirKey));
  console.log(`empty slot: ${empty}; counterparty signature verified: ${theirOk}`);
  console.log(`initiator delegation_${empty === 'a' ? 'b' : 'a'}: ` +
              `${a.tagValue(half, empty === 'a' ? 'delegation_b' : 'delegation_a') || 'EMPTY'}`);
  if (!theirOk) process.exit(1);

  const full = a.agreement(k.agent, delegationId, {
    intentId: a.tagValue(half, 'intent'), offerId: a.tagValue(half, 'offer'),
    price: price[1], currency: price[2], deadline: a.tagValue(half, 'deadline'),
    agentA: a.tagValue(half, 'agent_a'), agentB: a.tagValue(half, 'agent_b'),
    sigA: empty === 'a' ? a.signDigest(digest, k.agent) : a.tagValue(half, 'sig_a'),
    sigB: empty === 'b' ? a.signDigest(digest, k.agent) : a.tagValue(half, 'sig_b'),
    delegationA: a.tagValue(half, 'delegation_a') || (empty === 'a' ? delegationId : ''),
    delegationB: a.tagValue(half, 'delegation_b') || (empty === 'b' ? delegationId : ''),
  });
  const res = await relay.publish(full);
  if (!res.ok) { console.error('completed agreement rejected:', res.reason); process.exit(1); }
  console.log(`agreement completed: ${full.id}`);
  relay.close();
}

main().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
