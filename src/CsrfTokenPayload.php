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
 * Stored CSRF token payload.
 */
final class CsrfTokenPayload
{
    public function __construct(
        private readonly string $value,
        private readonly int $createdAt,
        private readonly ?int $expiresAt = null,
        private readonly bool $singleUse = false,
    ) {
    }

    public static function create(string $value, int $ttl = 3600, bool $singleUse = false): self
    {
        $now = time();

        return new self(
            value: $value,
            createdAt: $now,
            expiresAt: $ttl > 0 ? $now + $ttl : null,
            singleUse: $singleUse,
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        if (!isset($data['value']) || !is_string($data['value']) || $data['value'] === '') {
            return null;
        }

        return new self(
            value: $data['value'],
            createdAt: isset($data['created_at']) ? (int) $data['created_at'] : time(),
            expiresAt: isset($data['expires_at']) && $data['expires_at'] !== null ? (int) $data['expires_at'] : null,
            singleUse: isset($data['single_use']) && (bool) $data['single_use'],
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'value' => $this->value,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'single_use' => $this->singleUse,
        ];
    }

    public function value(): string
    {
        return $this->value;
    }

    public function createdAt(): int
    {
        return $this->createdAt;
    }

    public function expiresAt(): ?int
    {
        return $this->expiresAt;
    }

    public function singleUse(): bool
    {
        return $this->singleUse;
    }

    public function isExpired(?int $now = null): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return ($now ?? time()) >= $this->expiresAt;
    }
}