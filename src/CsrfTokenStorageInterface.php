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
 * Stores and retrieves CSRF tokens.
 */
interface CsrfTokenStorageInterface
{
    /**
     * Get a token value by token ID.
     *
     * @param string $id Token ID.
     *
     * @return string|null Token value or null if missing.
     */
    public function get(string $id): ?string;

    /**
     * Store a token value.
     *
     * @param string $id    Token ID.
     * @param string $token Token value.
     */
    public function set(string $id, string $token): void;

    /**
     * Check whether a token exists.
     *
     * @param string $id Token ID.
     */
    public function has(string $id): bool;

    /**
     * Remove a token.
     *
     * @param string $id Token ID.
     */
    public function remove(string $id): void;

    /**
     * Clear all CSRF tokens.
     */
    public function clear(): void;
}