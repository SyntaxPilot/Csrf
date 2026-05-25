<?php
/**
 * Copyright (c) 2027 Nicholas English
 *
 * This file is licensed under the MIT License.
 * See the LICENSE file in the project root for full license information.
 */

declare(strict_types=1);

namespace SyntaxPilot\Security\Csrf;

use SyntaxPilot\Security\Csrf\Contract\CsrfTokenGeneratorInterface;
use SyntaxPilot\Security\Csrf\Exception\ExpiredCsrfTokenException;
use SyntaxPilot\Security\Csrf\Exception\InvalidCsrfTokenException;
use SyntaxPilot\Security\Csrf\Exception\MissingCsrfTokenException;

/**
 * Manages CSRF tokens.
 */
final class CsrfTokenManager
{
    public function __construct(
        private readonly CsrfTokenStorageInterface $storage,
        private readonly CsrfTokenGeneratorInterface $generator = new CsrfTokenGenerator(),
        private readonly CsrfTokenConfig $config = new CsrfTokenConfig(),
    ) {
    }

    public function getToken(string $id): CsrfToken
    {
        $payload = $this->storage->get($id);

        if (!$payload instanceof CsrfTokenPayload || $payload->isExpired()) {
            return $this->refreshToken($id);
        }

        return new CsrfToken(
            id: $id,
            value: $payload->value(),
            expiresAt: $payload->expiresAt(),
        );
    }

    public function refreshToken(string $id): CsrfToken
    {
        $payload = CsrfTokenPayload::create(
            value: $this->generator->generate(),
            ttl: $this->config->ttl(),
            singleUse: $this->config->singleUse(),
        );

        $this->storage->set($id, $payload);

        return new CsrfToken(
            id: $id,
            value: $payload->value(),
            expiresAt: $payload->expiresAt(),
        );
    }

    public function hasToken(string $id): bool
    {
        $payload = $this->storage->get($id);

        return $payload instanceof CsrfTokenPayload && !$payload->isExpired();
    }

    public function validate(string $id, ?string $value): CsrfTokenResult
    {
        if (!is_string($value) || $value === '') {
            return CsrfTokenResult::missing();
        }

        $payload = $this->storage->get($id);

        if (!$payload instanceof CsrfTokenPayload) {
            return CsrfTokenResult::unknown();
        }

        if ($payload->isExpired()) {
            $this->storage->remove($id);

            return CsrfTokenResult::expired();
        }

        if (!hash_equals($payload->value(), $value)) {
            return CsrfTokenResult::mismatch();
        }

        if ($payload->singleUse()) {
            $this->storage->remove($id);
        }

        return CsrfTokenResult::valid();
    }

    public function isTokenValid(string $id, ?string $value): bool
    {
        return $this->validate($id, $value)->isValid();
    }

    public function validateOrFail(string $id, ?string $value): void
    {
        $result = $this->validate($id, $value);

        if ($result->isValid()) {
            return;
        }

        throw match ($result->reason()) {
            'missing' => new MissingCsrfTokenException('Missing CSRF token.'),
            'expired' => new ExpiredCsrfTokenException('Expired CSRF token.'),
            default => new InvalidCsrfTokenException('Invalid CSRF token.'),
        };
    }

    public function removeToken(string $id): void
    {
        $this->storage->remove($id);
    }

    public function clearTokens(): void
    {
        $this->storage->clear();
    }

    public function prune(): void
    {
        $this->storage->prune();
    }

    public function fieldName(): string
    {
        return $this->config->fieldName();
    }

    public function idFieldName(): string
    {
        return $this->config->idFieldName();
    }

    public function headerName(): string
    {
        return $this->config->headerName();
    }

    public function input(string $id): string
    {
        $token = $this->getToken($id);

        return sprintf(
            '<input type="hidden" name="%s" value="%s">' . "\n" .
            '<input type="hidden" name="%s" value="%s">',
            htmlspecialchars($this->config->fieldName(), ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($token->value(), ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($this->config->idFieldName(), ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($token->id(), ENT_QUOTES, 'UTF-8'),
        );
    }

    /**
     * @return array<string, string>
     */
    public function metaTags(string $id): array
    {
        $token = $this->getToken($id);

        return [
            'csrf-token-id' => $token->id(),
            'csrf-token' => $token->value(),
        ];
    }
}