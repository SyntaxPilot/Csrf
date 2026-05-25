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
 * In-memory CSRF token storage.
 */
final class ArrayCsrfTokenStorage implements CsrfTokenStorageInterface
{
    /**
     * @var array<string, CsrfTokenPayload>
     */
    private array $tokens = [];

    public function get(string $id): ?CsrfTokenPayload
    {
        return $this->tokens[$id] ?? null;
    }

    public function set(string $id, CsrfTokenPayload $payload): void
    {
        $this->tokens[$id] = $payload;
    }

    public function has(string $id): bool
    {
        return isset($this->tokens[$id]);
    }

    public function remove(string $id): void
    {
        unset($this->tokens[$id]);
    }

    public function clear(): void
    {
        $this->tokens = [];
    }

    public function prune(): void
    {
        foreach ($this->tokens as $id => $payload) {
            if ($payload->isExpired()) {
                unset($this->tokens[$id]);
            }
        }
    }
}