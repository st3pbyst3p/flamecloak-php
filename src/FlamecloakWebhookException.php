<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/**
 * A notice that was refused. `code` is one of no_signature, malformed,
 * mismatch, outside_tolerance, not_a_notice: the same five words in every SDK.
 * A FlamecloakException, so one catch covers the SDK.
 */
final class FlamecloakWebhookException extends FlamecloakException
{
    public function __construct(
        public readonly string $reason,
        string $message,
    ) {
        parent::__construct($message, null);
    }
}
