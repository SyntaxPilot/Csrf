<?php

declare(strict_types=1);

namespace SyntaxPilot\Security\Csrf\Contract;

interface CsrfTokenExtractorInterface
{
    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $headers
     */
    public function extractToken(array $input, array $headers): ?string;

    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $headers
     */
    public function extractTokenId(array $input, array $headers): ?string;
}