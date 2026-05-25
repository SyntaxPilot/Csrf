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
 * Stores and retrieves CSRF token payloads.
 */
interface CsrfTokenStorageInterface
{
    public function get(string $id): ?CsrfTokenPayload;

    public function set(string $id, CsrfTokenPayload $payload): void;

    public function has(string $id): bool;

    public function remove(string $id): void;

    public function clear(): void;

    /**
     * Remove expired tokens.
     */
    public function prune(): void;
}