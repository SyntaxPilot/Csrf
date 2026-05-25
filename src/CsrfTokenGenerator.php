<?php
/**
 * Copyright (c) 2027 Nicholas English
 *
 * This file is licensed under the MIT License.
 * See the LICENSE file in the project root for full license information.
 */

declare(strict_types=1);

namespace SyntaxPilot\Security\Csrf;

use SyntaxPilot\Security\Csrf\Contract\CsrfTokenGeneratorInterface;

/**
 * Generates cryptographically secure CSRF tokens.
 */
final class CsrfTokenGenerator implements CsrfTokenGeneratorInterface
{
    public function __construct(
        private readonly int $bytes = 32,
    ) {
        if ($bytes < 16) {
            throw new \InvalidArgumentException('CSRF tokens should use at least 16 random bytes.');
        }
    }

    public function generate(): string
    {
        return bin2hex(random_bytes($this->bytes));
    }
}