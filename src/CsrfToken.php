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
    public function __construct(
        private readonly string $id,
        private readonly string $value,
        private readonly ?int $expiresAt = null,
    ) {
    }

    public function id(): string
    {
        return $this->id;
    }

    public function value(): string
    {
        return $this->value;
    }

    public function expiresAt(): ?int
    {
        return $this->expiresAt;
    }

    public function isExpired(?int $now = null): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return ($now ?? time()) >= $this->expiresAt;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}