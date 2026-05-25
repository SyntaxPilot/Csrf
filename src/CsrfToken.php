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
 * Represents a CSRF token.
 */
final class CsrfToken
{
    /**
     * Create a CSRF token.
     *
     * @param string $id    Token ID, usually tied to a form or action.
     * @param string $value Token value.
     */
    public function __construct(
        private readonly string $id,
        private readonly string $value,
    ) {
    }

    /**
     * Get the token ID.
     */
    public function id(): string
    {
        return $this->id;
    }

    /**
     * Get the token value.
     */
    public function value(): string
    {
        return $this->value;
    }

    /**
     * Convert token to string.
     */
    public function __toString(): string
    {
        return $this->value;
    }
}