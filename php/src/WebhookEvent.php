<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/**
 * A verified notice that a decision has an answer. NOT the answer: call
 * Flamecloak::collect($event->decisionId), which spends an approval once and
 * says `allowed`.
 *
 * `type` is decision.approved, decision.denied, decision.expired or ping; a
 * kind added later arrives as its own word.
 */
final class WebhookEvent
{
    public function __construct(
        /** The same for every retry of one notice. */
        public readonly string $id,
        public readonly string $type,
        public readonly ?string $createdAt,
        public readonly ?string $decisionId,
        public readonly ?string $action,
        /** The idempotencyKey your code gave authorize(), so the job can be found again. */
        public readonly ?string $idempotencyKey,
    ) {
    }

    /** @return array{id: string, type: string, createdAt: ?string, decisionId: ?string, action: ?string, idempotencyKey: ?string} */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'createdAt' => $this->createdAt,
            'decisionId' => $this->decisionId,
            'action' => $this->action,
            'idempotencyKey' => $this->idempotencyKey,
        ];
    }
}
