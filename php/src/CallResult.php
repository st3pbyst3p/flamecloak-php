<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/**
 * What a call through your gateway came to.
 *
 * `outcome` is one of: answered (your endpoint answered; `status`, `headers`
 * and `body` are its answer, whatever the status); executed (the gateway held
 * the call, a person approved it, and the gateway made it, once: `status` is
 * what your endpoint answered); attempted (held and sent, and no answer came:
 * it may have run, and it is never sent again); refused (the gateway refused
 * it and waiting would not change that: see `reason` and `detail`); pending
 * (still waiting when `maxWaitSeconds` ran out: call again with `decisionId`);
 * or unavailable (your endpoint or the gateway could not be reached).
 */
final class CallResult
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly string $outcome,
        public readonly ?int $status = null,
        /** The answer's headers, names in lowercase; empty when the answer was the gateway's own record. */
        public readonly array $headers = [],
        /** The answer's body; null for a held call, whose response the gateway does not keep. */
        public readonly ?string $body = null,
        public readonly ?string $decisionId = null,
        /** Whether the gateway was holding the call to make it itself. */
        public readonly bool $held = false,
        public readonly ?string $reason = null,
        public readonly ?string $detail = null,
    ) {
    }

    /** @return array{outcome: string, status: ?int, headers: array<string, string>, body: ?string, decisionId: ?string, held: bool, reason: ?string, detail: ?string} */
    public function toArray(): array
    {
        return [
            'outcome' => $this->outcome,
            'status' => $this->status,
            'headers' => $this->headers,
            'body' => $this->body,
            'decisionId' => $this->decisionId,
            'held' => $this->held,
            'reason' => $this->reason,
            'detail' => $this->detail,
        ];
    }
}
