<?php

declare(strict_types=1);

namespace SyntaxPilot\Security\Csrf;

use SyntaxPilot\Security\Csrf\Contract\CsrfTokenExtractorInterface;

/**
 * Extracts CSRF tokens from request data.
 */
final class CsrfTokenExtractor implements CsrfTokenExtractorInterface
{
    public function __construct(
        private readonly CsrfTokenConfig $config = new CsrfTokenConfig(),
    ) {
    }

    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $headers
     */
    public function extractToken(array $input, array $headers): ?string
    {
        $fromInput = $input[$this->config->fieldName()] ?? null;

        if (is_string($fromInput) && $fromInput !== '') {
            return $fromInput;
        }

        $fromHeader = $this->header($headers, $this->config->headerName());

        return $fromHeader !== '' ? $fromHeader : null;
    }

    /**
     * @param array<string, mixed> $input
     * @param array<string, mixed> $headers
     */
    public function extractTokenId(array $input, array $headers): ?string
    {
        $fromInput = $input[$this->config->idFieldName()] ?? null;

        if (is_string($fromInput) && $fromInput !== '') {
            return $fromInput;
        }

        $fromHeader = $this->header($headers, 'X-CSRF-Token-ID');

        return $fromHeader !== '' ? $fromHeader : null;
    }

    /**
     * @param array<string, mixed> $headers
     */
    private function header(array $headers, string $name): string
    {
        foreach ($headers as $key => $value) {
            if (!is_string($key)) {
                continue;
            }

            if (strcasecmp($key, $name) !== 0) {
                continue;
            }

            return is_string($value) ? $value : '';
        }

        return '';
    }
}