<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/**
 * What the gateway said, or what this SDK says for it while it cannot be reached.
 *
 * `status` is one of allowed, pending, approved, used, denied, expired,
 * no_approver, unregistered, refused, stale or unavailable.
 */
final class Decision
{
    public function __construct(
        private readonly Flamecloak $client,
        public readonly bool $allowed,
        public readonly string $status,
        /** The decision on record, or null (allowed at once, or refused before one was made). */
        public readonly ?string $decisionId,
        public readonly ?string $reason,
        public readonly ?string $detail,
        /** A signed token for the approval, when the gateway signs; for a resource server of your own. */
        public readonly ?string $token,
    ) {
    }

    /** Report what happened afterwards. Optional; see Flamecloak::done(). */
    public function done(string $status, ?string $detail = null, ?string $reference = null): bool
    {
        return $this->client->done($this->decisionId, $status, $detail, $reference);
    }

    /** @return array{allowed: bool, status: string, decisionId: ?string, reason: ?string, detail: ?string, token: ?string} */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'status' => $this->status,
            'decisionId' => $this->decisionId,
            'reason' => $this->reason,
            'detail' => $this->detail,
            'token' => $this->token,
        ];
    }

    public function __debugInfo(): array
    {
        return $this->toArray();
    }
}
