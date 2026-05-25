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
 * CSRF token configuration.
 */
final class CsrfTokenConfig
{
    public function __construct(
        private readonly int $ttl = 3600,
        private readonly bool $singleUse = false,
        private readonly string $fieldName = '_csrf_token',
        private readonly string $idFieldName = '_csrf_token_id',
        private readonly string $headerName = 'X-CSRF-Token',
    ) {
        if ($ttl < 0) {
            throw new \InvalidArgumentException('CSRF token TTL cannot be negative.');
        }

        if ($fieldName === '') {
            throw new \InvalidArgumentException('CSRF token field name cannot be empty.');
        }

        if ($idFieldName === '') {
            throw new \InvalidArgumentException('CSRF token ID field name cannot be empty.');
        }

        if ($headerName === '') {
            throw new \InvalidArgumentException('CSRF token header name cannot be empty.');
        }
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    public function singleUse(): bool
    {
        return $this->singleUse;
    }

    public function fieldName(): string
    {
        return $this->fieldName;
    }

    public function idFieldName(): string
    {
        return $this->idFieldName;
    }

    public function headerName(): string
    {
        return $this->headerName;
    }
}