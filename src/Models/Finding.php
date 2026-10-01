<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Models;

use EidCloud\SecretHunter\Entropy\ShannonEntropy;

/**
 * Represents a single detected secret occurrence.
 */
class Finding
{
    public readonly string $maskedSecret;
    public readonly float $entropy;

    public function __construct(
        public readonly string $ruleId,
        public readonly string $ruleName,
        public readonly string $severity,
        public readonly string $category,
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly string $rawSecret,
        public readonly string $snippet = '',
        ?string $maskedSecret = null,
        ?float $entropy = null,
        public readonly ?string $commitHash = null,
        public readonly ?string $commitAuthor = null,
        public readonly ?string $commitDate = null
    ) {
        $this->maskedSecret = $maskedSecret ?? self::maskSecret($this->rawSecret);
        $this->entropy = $entropy ?? ShannonEntropy::calculate($this->rawSecret);
    }

    /**
     * Smart secret masking that preserves well-known prefixes while redacting sensitive entropy.
     * Example: sk-proj-12345678abcdef -> sk-proj-****cdef
     */
    public static function maskSecret(string $secret): string
    {
        $len = strlen($secret);
        if ($len <= 4) {
            return '****';
        }

        // Known prefixes to preserve
        $prefixes = [
            'sk-proj-',
            'sk-admin-',
            'sk-ant-api03-',
            'sk-ant-',
            'sk_live_',
            'rk_live_',
            'github_pat_',
            'ghp_',
            'gho_',
            'ghu_',
            'ghs_',
            'AIza',
            'xoxb-',
            'xoxp-',
            'xoxr-',
            'xoxs-',
            'SG.',
            'sq0atp-',
            'shpat_',
            'shpca_',
            'pypi-',
            'npm_',
        ];

        foreach ($prefixes as $p) {
            if (str_starts_with($secret, $p)) {
                $pLen = strlen($p);
                $remaining = substr($secret, $pLen);
                if (strlen($remaining) <= 4) {
                    return $p . '****';
                }
                $tail = substr($remaining, -4);
                return $p . '****' . $tail;
            }
        }

        if ($len <= 8) {
            return substr($secret, 0, 2) . '****' . substr($secret, -2);
        }

        // Default: keep 4 chars at beginning and 4 at the end
        return substr($secret, 0, 4) . '****' . substr($secret, -4);
    }

    /**
     * Convert finding to array for reporting and JSON serialization.
     */
    public function toArray(bool $mask = true): array
    {
        return [
            'rule_id'       => $this->ruleId,
            'rule_name'     => $this->ruleName,
            'severity'      => $this->severity,
            'category'      => $this->category,
            'file'          => $this->file,
            'line'          => $this->line,
            'column'        => $this->column,
            'secret'        => $mask ? $this->maskedSecret : $this->rawSecret,
            'entropy'       => $this->entropy,
            'snippet'       => $this->snippet,
            'commit_hash'   => $this->commitHash,
            'commit_author' => $this->commitAuthor,
            'commit_date'   => $this->commitDate,
        ];
    }
}
