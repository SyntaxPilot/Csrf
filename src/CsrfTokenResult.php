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
 * CSRF validation result.
 */
final class CsrfTokenResult
{
    private function __construct(
        private readonly bool $valid,
        private readonly string $reason = '',
    ) {
    }

    public static function valid(): self
    {
        return new self(true);
    }

    public static function missing(): self
    {
        return new self(false, 'missing');
    }

    public static function unknown(): self
    {
        return new self(false, 'unknown');
    }

    public static function expired(): self
    {
        return new self(false, 'expired');
    }

    public static function mismatch(): self
    {
        return new self(false, 'mismatch');
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function isInvalid(): bool
    {
        return !$this->valid;
    }

    public function reason(): string
    {
        return $this->reason;
    }
}