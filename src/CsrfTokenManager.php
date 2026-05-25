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
 * Manages CSRF tokens.
 */
final class CsrfTokenManager
{
    public function __construct(
        private readonly CsrfTokenStorageInterface $storage,
        private readonly CsrfTokenGenerator $generator = new CsrfTokenGenerator(),
    ) {
    }

    /**
     * Get an existing token or generate one if missing.
     *
     * @param string $id Token ID, usually tied to a form or action.
     */
    public function getToken(string $id): CsrfToken
    {
        $value = $this->storage->get($id);

        if (!is_string($value) || $value === '') {
            $value = $this->generator->generate();

            $this->storage->set($id, $value);
        }

        return new CsrfToken($id, $value);
    }

    /**
     * Generate and store a fresh token.
     *
     * @param string $id Token ID.
     */
    public function refreshToken(string $id): CsrfToken
    {
        $value = $this->generator->generate();

        $this->storage->set($id, $value);

        return new CsrfToken($id, $value);
    }

    /**
     * Check whether a token exists.
     */
    public function hasToken(string $id): bool
    {
        return $this->storage->has($id);
    }

    /**
     * Validate a submitted token value.
     *
     * @param string      $id    Token ID.
     * @param string|null $value Submitted token value.
     */
    public function isTokenValid(string $id, ?string $value): bool
    {
        if (!is_string($value) || $value === '') {
            return false;
        }

        $known = $this->storage->get($id);

        return is_string($known) && $known !== '' && hash_equals($known, $value);
    }

    /**
     * Validate a submitted CsrfToken object.
     */
    public function isCsrfTokenValid(CsrfToken $token): bool
    {
        return $this->isTokenValid($token->id(), $token->value());
    }

    /**
     * Remove a token.
     */
    public function removeToken(string $id): void
    {
        $this->storage->remove($id);
    }

    /**
     * Remove all CSRF tokens.
     */
    public function clearTokens(): void
    {
        $this->storage->clear();
    }
}