<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/**
 * Flamecloak for PHP: ask before your code acts.
 *
 *     $flamecloak = new \Flamecloak\Flamecloak(getenv('FLAMECLOAK_KEY'));
 *     $decision = $flamecloak->authorize('refund', resource: "payment:$paymentId", parameters: ['amount' => 1200]);
 *     if ($decision->allowed) {
 *         $stripe->refunds->create([...], ['idempotency_key' => $decision->decisionId]);
 *     }
 *
 * PHP 8.1+, the curl extension, no framework. The JavaScript and Python SDKs
 * behave the same way, call for call: all three are tested against the same
 * recorded exchanges.
 *
 * WHAT THROWS AND WHAT DOES NOT. A key that is not one, or a call the gateway
 * cannot read, throws FlamecloakException - the developer sees it on the first
 * test run instead of reading it as a refusal. The gateway being unreachable
 * NEVER throws: authorize() answers from the plan it last read (observe is
 * allowed, gate and deny are refused), so our outage never blocks what you did
 * not ask us to guard and never opens what you did.
 *
 * THE PLAN IS KEPT IN A FILE, by default in the system's temporary directory.
 * A PHP process usually lives for one web request, and a plan held only in
 * memory would be fetched again on every one of them. It holds action names and
 * modes, nothing else; `plan_cache => false` keeps it in memory only.
 */
final class Flamecloak
{
    public const VERSION = '0.1.0';

    private const KEY = '/^fc_[0-9a-z]{8}_[0-9a-z]{32}$/';
    private const NO_KEY = 'no key was given: the App key screen in the Flamecloak dashboard issues one, and FLAMECLOAK_KEY is where the snippets read it from';
    /** The gateway's own rule for the address after the @ (credentials.ts, KEY_ADDRESS). */
    private const ADDRESS = '/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?$/';
    private const DEFAULT_REFRESH_SECONDS = 60.0;
    /** The gateway holds a long-poll for at most this long. */
    private const LONG_POLL_SECONDS = 25;
    private const UNREACHABLE = 'unreachable';
    private const KEPT = 'the gateway could not be reached; the decision is kept there, so ask again with wait() or collect()';

    /** Where this client's calls go. */
    public readonly string $baseUrl;
    private readonly string $credential;
    private readonly float $timeout;
    /** @var callable(): float */
    private $clock;
    private readonly ?string $planFile;
    /** @var array{refuse_unknown: bool, refresh_seconds: float, modes: array<string, string>}|null */
    private ?array $plan = null;
    private ?float $planAskedAt = null;

    /**
     * @param array{base_url?: string, timeout?: float|int, plan_cache?: string|false, clock?: callable(): float} $options
     *   `base_url` only for a key that carries no address, or a self-hosted gateway.
     *   `timeout` is one request's, in seconds; a long-poll gets it on top of its wait.
     *   `plan_cache` is a directory for the plan, or false for memory only.
     *   `clock` is a clock in seconds, for tests.
     */
    public function __construct(string|false|null $key, array $options = [])
    {
        if (!\extension_loaded('curl')) {
            throw new FlamecloakException('the curl extension is not loaded, and this SDK sends its requests with it');
        }
        [$this->baseUrl, $this->credential] = self::readKey($key, $options['base_url'] ?? null);
        $this->timeout = (float) ($options['timeout'] ?? 10.0);
        $this->clock = $options['clock'] ?? static fn (): float => \microtime(true);
        $cache = $options['plan_cache'] ?? \sys_get_temp_dir();
        $this->planFile = $cache === false ? null : \rtrim((string) $cache, '/\\') . \DIRECTORY_SEPARATOR
            . 'flamecloak-plan-' . \substr($this->credential, 3, 8) . '-' . \substr(\hash('sha256', $this->baseUrl), 0, 8) . '.json';
        $this->loadPlanFile();
    }

    /** The header the gateway signs a notice with. */
    public const WEBHOOK_SIGNATURE_HEADER = 'flamecloak-signature';
    private const WEBHOOK_TOLERANCE_SECONDS = 300;

    /**
     * Check a notice from your gateway and read it.
     *
     *     $event = Flamecloak::verifyWebhook(
     *         file_get_contents('php://input'),
     *         $_SERVER['HTTP_FLAMECLOAK_SIGNATURE'] ?? null,
     *         getenv('FLAMECLOAK_WEBHOOK_SECRET'),
     *     );
     *
     * `$payload` is the RAW body as it arrived: decoded and re-encoded JSON is
     * different bytes, and does not verify. The header is
     * `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, keyed with the
     * whole secret; a signature further than `$tolerance` seconds from now,
     * either way, is refused, so a captured request cannot be replayed later.
     *
     * A notice is NOT the permission: collect() the decision it names.
     *
     * @throws FlamecloakWebhookException with `reason` no_signature, malformed,
     *   mismatch, outside_tolerance or not_a_notice
     */
    public static function verifyWebhook(
        string $payload,
        ?string $signature,
        string $secret,
        int $tolerance = self::WEBHOOK_TOLERANCE_SECONDS,
        ?int $now = null,
    ): WebhookEvent {
        if ($secret === '') {
            throw new \InvalidArgumentException('verifyWebhook needs the webhook secret the dashboard showed you');
        }
        if ($signature === null || \trim($signature) === '') {
            throw new FlamecloakWebhookException('no_signature', 'there is no ' . self::WEBHOOK_SIGNATURE_HEADER . ' header, so this did not come from your gateway');
        }

        $time = null;
        $signatures = [];
        foreach (\explode(',', $signature) as $part) {
            $at = \strpos($part, '=');
            if ($at === false) {
                continue;
            }
            $name = \trim(\substr($part, 0, $at));
            $value = \trim(\substr($part, $at + 1));
            if ($name === 't') {
                $time = $value;
            } elseif ($name === 'v1') {
                $signatures[] = $value;
            }
        }
        if ($time === null || \preg_match('/^[0-9]+$/', $time) !== 1 || $signatures === []) {
            throw new FlamecloakWebhookException('malformed', 'the ' . self::WEBHOOK_SIGNATURE_HEADER . ' header is not t=<time>,v1=<signature>');
        }

        $expected = \hash_hmac('sha256', $time . '.' . $payload, $secret);
        $matched = false;
        foreach ($signatures as $each) {
            // hash_equals takes the same time however much matches.
            $matched = \hash_equals($expected, $each) || $matched;
        }
        if (!$matched) {
            throw new FlamecloakWebhookException('mismatch', 'the signature does not match this body and this secret');
        }

        $moment = $now ?? \time();
        $drift = $moment - (int) $time;
        if (\abs($drift) > $tolerance) {
            throw new FlamecloakWebhookException(
                'outside_tolerance',
                "this was signed $drift seconds from now, more than $tolerance either way: a replay, or a clock that is wrong",
            );
        }

        // An OBJECT, told apart from a list: json_decode to an array cannot
        // tell `{}` from `[]`, so it is decoded as objects.
        try {
            $notice = \json_decode($payload, false, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $notice = null;
        }
        if (!$notice instanceof \stdClass || !\is_string($notice->id ?? null) || !\is_string($notice->type ?? null)) {
            throw new FlamecloakWebhookException('not_a_notice', 'the body is signed, and it is not a notice: a JSON object with an id and a type');
        }
        $text = static fn (mixed $value): ?string => \is_string($value) ? $value : null;
        return new WebhookEvent(
            $notice->id,
            $notice->type,
            $text($notice->created_at ?? null),
            $text($notice->decision ?? null),
            $text($notice->action ?? null),
            $text($notice->idempotency_key ?? null),
        );
    }

    /**
     * Where calls go and what is sent as the credential. Throws for a key that cannot be used.
     *
     * @return array{0: string, 1: string} [baseUrl, credential]
     */
    public static function readKey(string|false|null $key, ?string $baseUrl = null): array
    {
        // getenv() of a variable that is not set is false, and the Code
        // screen's snippet passes it as it is: that is a message, not a TypeError.
        $whole = \is_string($key) ? \trim($key) : '';
        if ($whole === '') {
            throw new FlamecloakException(self::NO_KEY);
        }
        $at = \strpos($whole, '@');
        $credential = $at === false ? $whole : \substr($whole, 0, $at);
        $address = $at === false ? null : \substr($whole, $at + 1);
        if (\preg_match(self::KEY, $credential) !== 1) {
            throw new FlamecloakException('that is not a Flamecloak key: they look like fc_<8 characters>_<32 characters>@<your gateway>');
        }
        if ($address !== null && \preg_match(self::ADDRESS, $address) !== 1) {
            throw new FlamecloakException('the part of the key after the @ is not an address: a lowercase host with an optional port');
        }
        if ($baseUrl !== null) {
            if (\preg_match('#^https?://[^/\s]+#i', $baseUrl) !== 1) {
                throw new FlamecloakException('base_url is an http or https address');
            }
            return [\rtrim($baseUrl, '/'), $credential];
        }
        if ($address === null) {
            throw new FlamecloakException('this key carries no address, so give the gateway\'s address as base_url');
        }
        return ['https://' . $address, $credential];
    }

    /**
     * May this action happen? Waits for a person when one has to decide, unless
     * `wait: false`, and collects the approval, so `allowed` means go ahead - once.
     *
     * `resource` and `parameters` are kept in the signed record for good: an
     * opaque id, never an email address.
     *
     * @param array<string, mixed>|null $parameters
     */
    public function authorize(
        string $action,
        ?string $resource = null,
        ?string $agent = null,
        ?array $parameters = null,
        ?string $idempotencyKey = null,
        bool $wait = true,
        int|float|null $maxWaitSeconds = null,
    ): Decision {
        $this->refreshPlan();
        $body = ['action' => $action];
        if ($resource !== null) {
            $body['resource'] = $resource;
        }
        if ($agent !== null) {
            $body['agent'] = $agent;
        }
        if ($parameters !== null) {
            // An empty PHP array is `[]` in JSON, and the gateway reads parameters as an object.
            $body['parameters'] = $parameters === [] ? new \stdClass() : $parameters;
        }
        if ($idempotencyKey !== null) {
            $body['idempotency_key'] = $idempotencyKey;
        }
        $answer = $this->send('POST', '/v1/actions/authorize', $body);
        if ($answer === null) {
            [$allowed, $detail] = $this->fromPlan($action);
            return new Decision($this, $allowed, $allowed ? 'allowed' : 'unavailable', null, self::UNREACHABLE, $detail, null);
        }
        $decision = $this->read($answer);
        if ($wait && $decision->decisionId !== null && \in_array($decision->status, ['pending', 'approved'], true)) {
            return $this->wait($decision->decisionId, $maxWaitSeconds);
        }
        return $decision;
    }

    /** Wait for a person's answer on a decision kept earlier, and collect it once there is one. */
    public function wait(string $decisionId, int|float|null $maxWaitSeconds = null): Decision
    {
        $deadline = $maxWaitSeconds === null ? null : ($this->clock)() + $maxWaitSeconds;
        $reason = null;
        while (true) {
            $seconds = self::LONG_POLL_SECONDS;
            if ($deadline !== null) {
                $left = $deadline - ($this->clock)();
                if ($left <= 0) {
                    return new Decision($this, false, 'pending', $decisionId, $reason, null, null);
                }
                $seconds = (int) \min(self::LONG_POLL_SECONDS, \ceil($left));
            }
            $answer = $this->send('GET', '/v1/decisions/' . \rawurlencode($decisionId) . '/long-poll?wait=' . $seconds, null, $seconds + $this->timeout);
            if ($answer === null || !\is_string($answer['state'] ?? null)) {
                return $this->kept($decisionId);
            }
            $reason = \is_string($answer['reason'] ?? null) ? $answer['reason'] : null;
            if ($answer['state'] !== 'pending') {
                return $this->collect($decisionId);
            }
        }
    }

    /** Spend an approval: `allowed` once, and never again. Does not wait. */
    public function collect(string $decisionId): Decision
    {
        $answer = $this->send('POST', '/v1/actions/decisions/' . \rawurlencode($decisionId) . '/collect', new \stdClass());
        return $answer === null ? $this->kept($decisionId) : $this->read($answer);
    }

    /**
     * Report what happened after an allowed action: `succeeded` or `failed`.
     *
     * Optional, once per decision, and your claim rather than something we
     * observed. False when there is no decision to report on, or the report could
     * not be delivered: this never throws for an outage, because the action has
     * already happened.
     */
    public function done(?string $decisionId, string $status, ?string $detail = null, ?string $reference = null): bool
    {
        if ($decisionId === null) {
            return false;
        }
        $body = ['status' => $status];
        if ($detail !== null) {
            $body['detail'] = $detail;
        }
        if ($reference !== null) {
            $body['reference'] = $reference;
        }
        return $this->send('POST', '/v1/actions/decisions/' . \rawurlencode($decisionId) . '/done', $body) !== null;
    }

    public function __debugInfo(): array
    {
        return ['baseUrl' => $this->baseUrl];
    }

    // ── inside ──────────────────────────────────────────────────────────────

    /** The plan, read at most once per refresh interval - also after a failure. */
    private function refreshPlan(): void
    {
        $now = ($this->clock)();
        $every = $this->plan['refresh_seconds'] ?? self::DEFAULT_REFRESH_SECONDS;
        if ($this->planAskedAt !== null && $now - $this->planAskedAt < $every) {
            return;
        }
        $this->planAskedAt = $now;
        $answer = $this->send('GET', '/v1/actions/plan', null);
        $plan = $answer === null ? null : self::readPlan($answer);
        if ($plan !== null) {
            $this->plan = $plan;
        }
        $this->savePlanFile();
    }

    /** @return array{refuse_unknown: bool, refresh_seconds: float, modes: array<string, string>}|null */
    private static function readPlan(mixed $body): ?array
    {
        if (!\is_array($body) || !\is_bool($body['refuse_unknown'] ?? null) || !\is_array($body['actions'] ?? null)) {
            return null;
        }
        $modes = [];
        foreach ($body['actions'] as $each) {
            if (!\is_array($each) || !\is_string($each['name'] ?? null) || !\is_string($each['mode'] ?? null)) {
                return null;
            }
            $modes[$each['name']] = $each['mode'];
        }
        $refresh = $body['refresh_seconds'] ?? null;
        return [
            'refuse_unknown' => $body['refuse_unknown'],
            'refresh_seconds' => (\is_int($refresh) || \is_float($refresh)) && $refresh > 0 ? (float) $refresh : self::DEFAULT_REFRESH_SECONDS,
            'modes' => $modes,
        ];
    }

    private function loadPlanFile(): void
    {
        if ($this->planFile === null || !\is_file($this->planFile)) {
            return;
        }
        $kept = \json_decode((string) @\file_get_contents($this->planFile), true);
        if (!\is_array($kept) || !\is_float($kept['asked_at'] ?? null) && !\is_int($kept['asked_at'] ?? null)) {
            return;
        }
        $this->planAskedAt = (float) $kept['asked_at'];
        $plan = \is_array($kept['plan'] ?? null) ? $kept['plan'] : null;
        if ($plan !== null && \is_bool($plan['refuse_unknown'] ?? null) && \is_array($plan['modes'] ?? null)) {
            $this->plan = [
                'refuse_unknown' => $plan['refuse_unknown'],
                'refresh_seconds' => (float) ($plan['refresh_seconds'] ?? self::DEFAULT_REFRESH_SECONDS),
                'modes' => \array_map('strval', $plan['modes']),
            ];
        }
    }

    /** Written whole and renamed into place, so a reader never sees half a file. Best effort. */
    private function savePlanFile(): void
    {
        if ($this->planFile === null) {
            return;
        }
        $json = \json_encode(['asked_at' => $this->planAskedAt, 'plan' => $this->plan]);
        $partial = $this->planFile . '.' . \bin2hex(\random_bytes(4));
        if ($json !== false && @\file_put_contents($partial, $json) !== false && !@\rename($partial, $this->planFile)) {
            @\unlink($partial);
        }
    }

    /**
     * What an outage answers for one name, from the plan last read.
     *
     * @return array{0: bool, 1: string}
     */
    private function fromPlan(string $action): array
    {
        if ($this->plan === null) {
            return [false, 'the gateway could not be reached, and no plan of its actions has been read yet, so nothing can be allowed'];
        }
        $mode = $this->plan['modes'][$action] ?? null;
        if ($mode === null) {
            return $this->plan['refuse_unknown']
                ? [false, 'the gateway could not be reached, and names nobody registered are refused, so it is refused']
                : [true, 'the gateway could not be reached, and names nobody registered are allowed, so it is allowed'];
        }
        // Anything but observe is refused, including a mode this SDK does not know:
        // an outage never opens what somebody asked to guard.
        return $mode === 'observe'
            ? [true, 'the gateway could not be reached, and this action is only observed, so it is allowed']
            : [false, 'the gateway could not be reached, and this action is guarded, so it is refused'];
    }

    /** @param array<string, mixed> $body */
    private function read(array $body): Decision
    {
        $text = static fn (string $name): ?string => \is_string($body[$name] ?? null) ? $body[$name] : null;
        return new Decision(
            $this,
            ($body['allowed'] ?? null) === true,
            $text('status') ?? 'denied',
            $text('decision'),
            $text('reason'),
            $text('detail'),
            $text('token'),
        );
    }

    private function kept(string $decisionId): Decision
    {
        return new Decision($this, false, 'unavailable', $decisionId, self::UNREACHABLE, self::KEPT, null);
    }

    /**
     * One request. A 2xx with a JSON object is an answer; a 4xx throws with the
     * gateway's own words; everything else - no connection, a timeout, a 5xx, a
     * 429, a body that is not JSON - is an outage, null.
     *
     * @param array<string, mixed>|\stdClass|null $body
     * @return array<string, mixed>|null
     */
    private function send(string $method, string $path, array|\stdClass|null $body, ?float $timeout = null): ?array
    {
        $headers = [
            'x-flamecloak-key: ' . $this->credential,
            'accept: application/json',
            'user-agent: flamecloak-php/' . self::VERSION,
            // curl asks "100-continue" before a larger body and waits for an answer to it.
            'expect:',
        ];
        $handle = \curl_init($this->baseUrl . $path);
        if ($handle === false) {
            return null;
        }
        $options = [
            \CURLOPT_CUSTOMREQUEST => $method,
            \CURLOPT_RETURNTRANSFER => true,
            \CURLOPT_FOLLOWLOCATION => false,
            \CURLOPT_TIMEOUT_MS => (int) \round(($timeout ?? $this->timeout) * 1000),
            \CURLOPT_CONNECTTIMEOUT_MS => (int) \round($this->timeout * 1000),
            \CURLOPT_PROTOCOLS => \CURLPROTO_HTTP | \CURLPROTO_HTTPS,
        ];
        if ($body !== null) {
            $headers[] = 'content-type: application/json';
            $options[\CURLOPT_POSTFIELDS] = \json_encode($body, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION | \JSON_THROW_ON_ERROR);
        }
        $options[\CURLOPT_HTTPHEADER] = $headers;
        \curl_setopt_array($handle, $options);
        $raw = \curl_exec($handle);
        $status = (int) \curl_getinfo($handle, \CURLINFO_RESPONSE_CODE);
        \curl_close($handle);
        if (!\is_string($raw)) {
            return null;
        }
        // Decoded twice: once to learn whether it is an OBJECT (an empty PHP
        // array cannot say), once into arrays to read.
        $shape = \json_decode($raw);
        $parsed = \json_decode($raw, true);
        if ($status >= 400 && $status < 500 && $status !== 429) {
            $said = \is_array($parsed) && \is_string($parsed['error'] ?? null) ? $parsed['error'] : "the gateway answered $status";
            throw new FlamecloakException($said, $status);
        }
        if ($status < 200 || $status >= 300 || !$shape instanceof \stdClass || !\is_array($parsed)) {
            return null;
        }
        return $parsed;
    }
}
