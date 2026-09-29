<?php
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flamecloak;

/** A key that is not one, or an answer from the gateway that means your code has a bug. */
class FlamecloakException extends \RuntimeException
{
    public function __construct(
        string $message,
        /** The HTTP status the gateway answered with, or null when nothing was sent. */
        public readonly ?int $httpStatus = null,
    ) {
        parent::__construct($message);
    }
}
