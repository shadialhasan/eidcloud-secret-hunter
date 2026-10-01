<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Rules;

use EidCloud\SecretHunter\Entropy\ShannonEntropy;

/**
 * Secret Detection Rule definition.
 */
class Rule
{
    /**
     * @param string $id Unique rule identifier
     * @param string $name Human readable name
     * @param string $pattern PCRE regex pattern
     * @param string $severity Severity level (critical, high, medium, low)
     * @param string $category Service or domain category
     * @param string $description Explanatory notes
     * @param float|null $entropyThreshold Minimum Shannon entropy required to trigger (reduces false positives)
     * @param int $matchGroup Capturing group containing the actual secret
     * @param (callable(string): bool)|null $validator Optional custom validator closure
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $pattern,
        public readonly string $severity = Severity::HIGH,
        public readonly string $category = 'Generic',
        public readonly string $description = '',
        public readonly ?float $entropyThreshold = null,
        public readonly int $matchGroup = 0,
        private readonly mixed $validator = null
    ) {
    }

    /**
     * Match a single line of text against this rule.
     *
     * @return array<int, array{secret: string, offset: int}>
     */
    public function matchLine(string $line): array
    {
        $matches = [];
        $res = @preg_match_all($this->pattern, $line, $rawMatches, PREG_OFFSET_CAPTURE);

        if ($res === false || empty($rawMatches[0])) {
            return [];
        }

        $targetGroup = $this->matchGroup;
        if (!isset($rawMatches[$targetGroup])) {
            $targetGroup = 0;
        }

        foreach ($rawMatches[$targetGroup] as $match) {
            $secret = $match[0];
            $offset = $match[1];

            // Entropy threshold check
            if ($this->entropyThreshold !== null) {
                $entropy = ShannonEntropy::calculate($secret);
                if ($entropy < $this->entropyThreshold) {
                    continue;
                }
            }

            // Custom validator check if provided
            if ($this->validator !== null && is_callable($this->validator)) {
                if (!($this->validator)($secret)) {
                    continue;
                }
            }

            $matches[] = [
                'secret' => $secret,
                'offset' => $offset,
            ];
        }

        return $matches;
    }
}
