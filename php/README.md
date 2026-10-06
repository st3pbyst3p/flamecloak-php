# Flamecloak for PHP

PHP 8.1+ with the curl extension. No framework and no other package.

```
composer require flamecloak/flamecloak
```

The developer guide, every status, and what to check before shipping:
[the Flamecloak developer guide](https://github.com/st3pbyst3p/flamecloak-php/blob/main/GUIDE.md).

```php
use Flamecloak\Flamecloak;

$flamecloak = new Flamecloak(getenv('FLAMECLOAK_KEY'));

$decision = $flamecloak->authorize(
    'refund',
    resource: "payment:$paymentId",
    agent: 'support-bot',
    parameters: ['amount' => 1200],
);

if ($decision->allowed) {
    $refund = $stripe->refunds->create(['payment_intent' => $paymentId, 'amount' => 1200], ['idempotency_key' => $decision->decisionId]);
    $decision->done('succeeded', reference: $refund->id); // optional
}
```

A web request that cannot wait asks without waiting and keeps the id:

```php
$asked = $flamecloak->authorize('refund', parameters: ['amount' => 1200], wait: false);
if ($asked->status === 'pending') {
    $jobs->save(['decision_id' => $asked->decisionId]);
}
// later
$decision = $flamecloak->collect($decisionId); // or $flamecloak->wait($decisionId, maxWaitSeconds: 60)
```

### Resuming the job when a person decides

Ask without waiting, with your job's own id as the idempotency key:

```php
$asked = $flamecloak->authorize('refund', parameters: ['amount' => 1200], idempotencyKey: $job->id, wait: false);
```

and resume it from the notice (see [Notices](https://github.com/st3pbyst3p/flamecloak-php/blob/main/GUIDE.md#notices-for-code-that-cannot-wait)),
reading the RAW body:

```php
use Flamecloak\Flamecloak;
use Flamecloak\FlamecloakWebhookException;

try {
    $event = Flamecloak::verifyWebhook(
        file_get_contents('php://input'),
        $_SERVER['HTTP_FLAMECLOAK_SIGNATURE'] ?? null,
        getenv('FLAMECLOAK_WEBHOOK_SECRET'),
    );
} catch (FlamecloakWebhookException $refused) { // $refused->reason says why
    http_response_code(400);
    exit;
}
if ($event->decisionId !== null && $event->idempotencyKey !== null) {
    $job = $jobs->find($event->idempotencyKey);
    if ($job !== null) {
        // THE NOTICE IS NOT THE PERMISSION; collect is, once.
        $decision = $flamecloak->collect($event->decisionId);
        if ($decision->allowed) {
            refund($job, idempotencyKey: $event->decisionId);
        } elseif ($decision->status !== 'used') { // denied, expired, stale
            $jobs->close($job, $decision->status);
        }
        // 'used': this notice came again after the job ran. Nothing to do.
    }
}
http_response_code(200);
```

A retried notice is harmless: its second collect answers `used`.

`new Flamecloak($key, ['base_url' => …, 'timeout' => 10, 'plan_cache' => …])`.
`base_url` only for a key with no address or a self-hosted gateway; `timeout`
is one request's, in seconds (a long-poll gets it on top of its wait).

**The plan is kept in a file** (`plan_cache`, by default the system's temporary
directory), because a PHP process usually lasts one web request and a plan kept
in memory would be fetched again on every one. It holds action names and modes
and nothing else. `'plan_cache' => false` keeps it in memory only.

`authorize()` also takes `publicInfo` (who asked and what changes, once your
organisation has turned on Say who asked; see the
[guide](https://github.com/st3pbyst3p/flamecloak-php/blob/main/GUIDE.md#saying-who-asked)).

Errors are `Flamecloak\FlamecloakException`, with `httpStatus` set to the
gateway's HTTP status, or `null` for a key that is not one. A refused notice
is its subclass `FlamecloakWebhookException`, with `reason`.

When Flamecloak sits in front of an endpoint, `call()` makes the call and
waits: a 403 `pending` is sent again byte for byte with the decision, and a
202 (held) is waited on until the gateway has made the call itself.

```php
$result = $flamecloak->call('https://api.example.com/api/orders/1');
// $result->outcome: answered, executed, attempted, refused, pending or unavailable
```

See [calls through your gateway](https://github.com/st3pbyst3p/flamecloak-php/blob/main/GUIDE.md#calls-through-your-gateway).

What every status means, what throws, and what to check before shipping: the
[developer guide](https://github.com/st3pbyst3p/flamecloak-php/blob/main/GUIDE.md#every-answer).

Apache License 2.0.
