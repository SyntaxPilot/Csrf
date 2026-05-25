<?php
/**
 * Copyright (c) 2027 Nicholas English
 *
 * This file is licensed under the MIT License.
 * See the LICENSE file in the project root for full license information.
 */

declare(strict_types=1);

namespace SyntaxPilot\Security\Csrf;

/**
 * Generates cryptographically secure CSRF tokens.
 */
final class CsrfTokenGenerator
{
    /**
     * Create a token generator.
     *
     * @param int $bytes Number of random bytes before hex encoding.
     */
    public function __construct(
        private readonly int $bytes = 32,
    ) {
    }

    /**
     * Generate a new CSRF token value.
     */
    public function generate(): string
    {
        return bin2hex(random_bytes($this->bytes));
    }
}