# Flamecloak in your code: the developer guide

This guide is for the developers adding Flamecloak to an application. It says
how the pieces fit, and what has to be true of your code for a Flamecloak
answer to protect anything, and it lists every status and every error. The
per-language details are on each SDK's page:

| Language | Package | Needs |
|---|---|---|
| JavaScript / TypeScript | [`flamecloak-sdk` on npm](https://www.npmjs.com/package/flamecloak-sdk) | Node 20+, Deno, Bun or an edge runtime (`fetch`, Web Crypto) |
| Python | [`flamecloak-sdk` on PyPI](https://pypi.org/project/flamecloak-sdk/) | Python 3.9+, standard library only |
| PHP | [`flamecloak/flamecloak`](https://github.com/st3pbyst3p/flamecloak-php#readme), on Packagist | PHP 8.1+ with curl |

None of them has a runtime dependency. All three are Apache 2.0.

## How it fits together

Your code is about to do something that matters: a refund, a transfer, closing
an account. Before it does, it calls `authorize()` with the name of that action
and the values it is about to use. The answer comes from the rules you set in
the Flamecloak dashboard, on the **Actions** screen:

- **observe**: allowed at once;
- **gate**: allowed at once when the action's conditions are not met; when they
  are, a person you named approves or refuses it with a passkey, before a
  deadline you chose;
- **deny**: refused, with a record.

A call that goes to a person, or is denied, becomes a decision in the signed
ledger of your own Flamecloak instance, with its resource and parameters. A
call allowed at once leaves no decision: the gateway only counts how often each
name is asked. The rules live in the dashboard, not in your code: changing who
approves a refund, or the
amount above which one is needed, is signed with a passkey there and takes
effect without a deploy.

## Getting started

1. **Register your actions** on the Actions screen: a name your code will use
   (`refund`, `wire.transfer`), a mode, conditions on the parameters, approvers
   and a deadline. You can also start with nothing registered: a name nobody
   registered is allowed, and shows up on the Actions screen as
   "seen in your code, not registered yet", with a button to register it. Once
   your list is complete, turn on the switch that refuses names it does not
   hold.
2. **Issue a key** on the App key screen. It is shown once. It looks like
   `fc_ab12cd34_<secret>@<your gateway>`: the part after the `@` is where the
   SDK sends its calls, and it is not secret; the part before it is. Put it in
   your application's environment as `FLAMECLOAK_KEY`.
3. **Install the SDK** and **paste the snippet** from the dashboard's **Code**
   screen. It has one for each of your actions, in each language, already
   carrying the action's name and the parameters its conditions read.

```
npm install flamecloak-sdk
pip install flamecloak-sdk
composer require flamecloak/flamecloak
```

## Asking

```ts
const flamecloak = new Flamecloak(process.env.FLAMECLOAK_KEY);

const decision = await flamecloak.authorize({
  action: 'refund',
  resource: `payment:${paymentId}`,
  agent: 'support-bot',
  parameters: { amount },
});

if (decision.allowed) {
  await stripe.refunds.create({ payment_intent: paymentId, amount }, { idempotencyKey: decision.decisionId ?? job.id });
}
```

- `action` is the registered name. It is the only field required.
- `parameters` are what the action's conditions are evaluated on. Send the
  values you are about to use, not a description of them.
- `resource` says what the call is about, such as `payment:pi_123`, and is
  shown to the person approving.
- `agent` is a label for which agent asked, such as `support-bot`. One key
  serves your whole organisation, so without it every decision shows the
  organisation as the requester. It is your word and we do not check it.

### Saying who asked

The person approving reads your organisation's key as the requester. When your
code knows who is behind the call, it can say so, and say what changes:

```ts
const decision = await flamecloak.authorize({
  action: 'change-email',
  resource: `account:${accountId}`,
  publicInfo: {
    requestedBy: 'ana@example.com',
    whatIsChanged: 'the email address on account 42',
    notes: 'asked by phone, ticket 7781',
  },
});
```

In Python it is `public_info={"requested_by": ..., "what_is_changed": ...,
"notes": ...}`, in PHP `publicInfo: ['requestedBy' => ..., 'whatIsChanged' =>
..., 'notes' => ...]`.

- It is shown first on the approval page, labelled as your application's
  statement. Flamecloak does not check it.
- Text only, up to 200, 500 and 1000 characters. A longer value, or a key not
  listed here, is refused, never cut.
- It is part of what the person signs, and it is kept in the signed record for
  good. A name or an email address in it can never be removed.
- It is off until your organisation turns on **Say who asked**, signed with a
  passkey, in the dashboard (Approvers). Until then `authorize()` with
  `publicInfo` throws a 400 that says so, rather than dropping it.
- It never goes into a notification: email, Telegram, Slack and push say only
  that a decision is waiting.

**`allowed: true` means go ahead, once.** When a person has to decide,
`authorize()` waits for them, long-polling up to the action's deadline (or
`maxWaitSeconds`), and then *collects* the approval, which spends it. Asking
again for the same thing is a new question.

**Reporting what happened is optional.** `decision.done({ status: 'succeeded',
reference: refund.id })` ends the record with "the refund happened". A record
without a report ends at "approved and collected" and says the outcome was not
reported; it never implies the action succeeded. A report is your claim, not
something Flamecloak observed.

## Every answer

`new Flamecloak(key)` is all the configuration there is. The key carries its
gateway's address after an `@` (`fc_ab12cd34_…@acme.gw.tunnelpowered.com`);
only the part before the `@` is the credential. A self-hosted gateway, or a key
without an address, takes the address as an option.

| Call | What it does |
|---|---|
| `authorize(action, …)` | May this happen? If a person has to decide, it **waits** for them (long-polling, 25 seconds at a time, until the decision's deadline or your own longest wait) and then collects the approval. `wait: false` answers `pending` at once instead. |
| `wait(decisionId)` | The waiting, for a decision you kept earlier. |
| `collect(decisionId)` | Spends an approval: `allowed: true` once, and never again. Does not wait. |
| `done(decisionId, status)` | Optional: reports what happened (`succeeded` or `failed`). Once per decision. |
| `call(url, …)` | A call to your own endpoint through the gateway in front of it, waiting for a person when it is gated. See [Calls through your gateway](#calls-through-your-gateway). |

Every answer is a decision: `allowed`, `status`, `decisionId`, `reason`,
`detail`, and `token` (a signed approval, when the gateway signs).

| `status` | Meaning |
|---|---|
| `allowed` | Go ahead. |
| `pending` | Nobody has answered yet. Keep `decisionId`; `wait()` or `collect()` later. |
| `approved` | A person said yes and nobody has collected it; `collect()` spends it. |
| `used` | This approval was already collected. One approval, one action. |
| `denied` | Refused, by a person or by the action's rule. |
| `expired` | Nobody answered before the deadline. |
| `no_approver` | Nobody who could approve this holds a passkey yet. |
| `unregistered` | Your organisation refuses names it has not registered, and this is one. |
| `refused` | The call carried something the action refuses, such as personal data. |
| `stale` | The action changed after this was approved. Ask again. |
| `unavailable` | The gateway could not be reached. See [When Flamecloak cannot be reached](#when-flamecloak-cannot-be-reached). |

## Notices, for code that cannot wait

A request handler, a serverless function or a queue worker cannot sit in
`authorize()` for fifteen minutes. Ask with `wait: false` and your own job id
as `idempotencyKey`; the answer is `pending` with a `decisionId`. Keep it with
the job. Then either call `collect(decisionId)` later, or register a URL on the
App key screen and let the gateway send a notice when a person decides. Each
SDK's page has the handler that resumes the job.

- **Register one URL** on the dashboard's App key screen. The secret it shows
  is shown **once**; replacing it stops the old one at once. The gateway posts
  a notice when a person approves (`decision.approved`), refuses
  (`decision.denied`), or nobody decides in time (`decision.expired`), and a
  `ping` when you press "send a test notice".
- **A notice is never the permission.** It carries the decision id, the action
  name and your idempotency key, and nothing to act on. Your handler calls
  `collect(decisionId)`, which spends an approval once and says `allowed`. A
  notice can arrive twice (the same `id` each time), and anybody who finds the
  URL can post to it; neither matters, because the second collect answers
  `used`.
- **Check every notice with `verifyWebhook()`** (`verify_webhook` in Python),
  on the raw body as it arrived. The header is
  `flamecloak-signature: t=<unix seconds>,v1=<hex>`, the hex being
  HMAC-SHA256 of `<t>.<body>` keyed with the whole secret. A signature more
  than five minutes from your clock, either way, is refused, so a captured
  notice cannot be replayed later. A refusal says why in one of five words:
  `no_signature`, `malformed`, `mismatch`, `outside_tolerance`, `not_a_notice`
  (`code` in JavaScript and Python, `reason` in PHP, whose exceptions already
  have an integer code).
- **Answer 2xx within ten seconds**, or the notice is tried again: after one
  minute, two, four, eight, then every half hour. An approval's notice is tried
  until the decision's deadline, after which the approval is worth nothing; a
  refusal's and an expiry's for an hour.
- **A managed gateway only posts to a public https address.** A self-hosted
  one can reach a private address when its environment says
  `WEBHOOK_PRIVATE_ADDRESSES=allow`.

## Calls through your gateway

When Flamecloak sits in front of an endpoint - your server sends those paths to
it - your code does not call `authorize()`: it calls the endpoint, and a gated
call is answered by the gateway instead of your application. `call()` makes
that call and does the waiting:

```js
const result = await flamecloak.call({
  url: 'https://api.example.com/api/payouts',
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ amount: 1250, to: 'acct-1' }),
});
if (result.outcome === 'answered') console.log(result.status, result.body);
```

```python
result = flamecloak.call(
    "https://api.example.com/api/payouts",
    method="POST",
    headers={"content-type": "application/json"},
    body='{"amount":1250,"to":"acct-1"}',
)
```

```php
$result = $flamecloak->call(
    'https://api.example.com/api/payouts',
    method: 'POST',
    headers: ['content-type' => 'application/json'],
    body: '{"amount":1250,"to":"acct-1"}',
);
```

- **A 423 `pending` is sent again, byte for byte.** (A gateway older than
  October 2026 answers 403; it is waited on the same way.) The same method, address,
  headers and body, with `x-flamecloak-decision`, on the gateway's
  `retry-after`, until a person answers. An approval covers one exact call: the
  body is read once and sent unchanged every time, so do not rebuild it between
  attempts yourself.
- **A 202 means the gateway is holding the call** to make it itself, once, when
  a person approves. `call()` then waits on the decision with your key, waits
  for the gateway's call, and says what your endpoint answered it. The
  response body is not kept by the gateway, so `body` is empty; ask your own
  application for what it did.
- **Your key never goes to your endpoint.** The server in front of it adds its
  own; your key is sent only to the gateway, to wait on a held call.
- `maxWaitSeconds` (`max_wait_seconds` in Python) bounds the wait; then the
  outcome is `pending` with `decisionId`, and calling again with that
  `decisionId` carries on instead of asking a person again.

| `outcome` | Meaning |
|---|---|
| `answered` | Your endpoint answered: `status`, `headers` and `body` are its answer, whatever the status. |
| `executed` | The gateway held the call, a person approved it, and the gateway made it: `status` is what your endpoint answered. |
| `attempted` | The gateway sent it and no answer came. It may have run, and it is never sent again: check your own application before doing anything. |
| `refused` | The gateway refused it and waiting will not change that: `reason` says why (`denied`, `expired`, …) and `detail` in the gateway's words. |
| `pending` | Still waiting when your longest wait ran out. Call again with `decisionId`. |
| `unavailable` | Your endpoint or the gateway could not be reached. A held call's decision is kept; call again with its id. |

`call()` throws only for a request it cannot make: an address that is not one,
or a body on a GET.

## Before you ship

Five things decide whether a Flamecloak answer protects anything. The Code
screen shows them beside the snippets, in these words.

### The application is honest, the agent is not.

The conditions are evaluated on the parameters your code sends. Send the same values you pass to the payment provider.

That is the trust model. The agent is the party being gated: it can ask for
anything, phrase it any way, and try again. Your code is not being gated: it
writes `authorize({ parameters: { amount } })` with the same `amount` it then
gives Stripe. Code that wanted to lie could skip `authorize()` altogether, so a
rule like "over 500 needs a person" is exactly as strong as your code's
promise to send the real amount. Pass the variable, never a copy of it that
the agent wrote.

### The agent must not hold the keys to what it is guarded from.

authorize() protects a refund only if the agent reaches Stripe through your code. An agent that holds the Stripe key can skip the question.

Give the agent a tool that calls your code, and keep the payment provider's
key, the database password and the admin token where only your code can read
them. The same goes for anything else an action guards.

### Use the decision's id as the idempotency key.

Give it to what you do next, such as Stripe's idempotency key. Then even a retry of your own code cannot turn one approval into two refunds.

In JavaScript that is `{ idempotencyKey: decision.decisionId }`, in Python
`idempotency_key=decision.decision_id`, in PHP
`['idempotency_key' => $decision->decisionId]`. Flamecloak spends an approval
once; the idempotency key makes the payment provider do the same, so a
timeout followed by a retry still refunds once. When a call is allowed at once
there is no decision on record and the id is empty: use your own job's id
there, as you would without Flamecloak.

### resource and parameters are kept for good.

Everything in them is kept in the signed record permanently. An opaque id is fine; an email address can never be removed. An action can be set to refuse personal data.

They are kept whenever a call becomes a decision: when a person is asked, and
when an action is denied. The ledger is append-only and signed, which is what
makes it evidence, and also why nothing written into it can be taken out
later. Send `user: "u_8831"`,
not a name or an address. An action with "refuse personal data" turned on
refuses a call whose parameters or resource look like personal data, with the
status `refused`, and keeps nothing of the call.

### A condition sees one call.

"Over 500" works; "more than three refunds for this customer today" does not.

A condition is evaluated on the parameters of the call in front of it and
nothing else: no history, no counts, no other calls. Something that needs a
count over time is a separate feature, not a condition you can write today.
A parameter a condition names that the call does not send is not read as
"not met": on a gated action it goes to a person, and on a denied one it is
refused.

## When Flamecloak cannot be reached

`authorize()` never throws because our side is down. Each SDK keeps a plan of
your actions' names and modes, refreshed once a minute, and answers from it: an
**observe** action is allowed; a **gated** or **denied** one is refused with
the status `unavailable`; a name nobody registered follows your switch. Before
the first plan has been read, nothing is allowed. Our outage never blocks an
action you did not ask us to guard, and never opens one you did.

What does throw is a mistake you should see on your first test run: a key that
is not a key, a key that is not set, or a call the gateway cannot read (such as
an action name with a space in it). `done()` answers `false` rather than
throwing when a report cannot be delivered, because by then the action has
happened.

## The key

- **One key per organisation.** Every call it makes is recorded as that key,
  and an approval raised under one key can be collected only with that key.
- **Replacing it stops the old one at once.** That is the right behaviour
  after a leak. When you are rotating on purpose and need time to deploy, ask
  for the old key to keep working for up to six hours; that request is signed
  with a passkey. Approvals still waiting under the old key are collected with
  the old key, which is what the overlap is for.

## Changing a rule

An action's rules change only when a person signs the change with a passkey on
the Actions screen, and the change is recorded with who and when. Changing an
action voids the approvals given under its old rules that nobody has collected
yet: collecting one answers `stale`, and your code asks again.
