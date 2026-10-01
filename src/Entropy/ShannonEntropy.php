<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Entropy;

/**
 * Shannon Entropy Analyzer for detecting high-randomness secret strings
 * such as API keys, tokens, and cryptographic keys.
 *
 * Shannon Entropy H = - SUM( p(x) * log2( p(x) ) )
 */
class ShannonEntropy
{
    /**
     * Default threshold for general alphanumeric tokens.
     */
    public const DEFAULT_THRESHOLD = 3.8;

    /**
     * Calculate raw Shannon entropy (in bits per character).
     *
     * Theoretical maximum for:
     * - Hexadecimal (16 chars): ~4.0
     * - Alphanumeric (62 chars): ~5.95
     * - Base64 (64 chars): ~6.0
     * - Full ASCII (95 printable chars): ~6.57
     */
    public static function calculate(string $string): float
    {
        $length = strlen($string);
        if ($length <= 1) {
            return 0.0;
        }

        $frequencies = count_chars($string, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return round($entropy, 4);
    }

    /**
     * Calculate normalized Shannon entropy between 0.0 (homogeneous) and 1.0 (maximum possible dispersion).
     */
    public static function calculateNormalized(string $string): float
    {
        $length = strlen($string);
        if ($length <= 1) {
            return 0.0;
        }

        $entropy = self::calculate($string);
        $maxPossibleEntropy = log(min($length, 95), 2);

        if ($maxPossibleEntropy <= 0.0) {
            return 0.0;
        }

        return round(min(1.0, $entropy / $maxPossibleEntropy), 4);
    }

    /**
     * Check if a string qualifies as high-entropy given a threshold.
     */
    public static function isHighEntropy(string $string, float $threshold = self::DEFAULT_THRESHOLD): bool
    {
        // Ignore very short strings (< 12 chars) as they have low statistical sample size
        if (strlen($string) < 12) {
            return false;
        }

        return self::calculate($string) >= $threshold;
    }

    /**
     * Check if a hex string exhibits high entropy (typical random hex >= 3.0, threshold 3.2).
     */
    public static function isHighEntropyHex(string $hex, float $threshold = 3.2): bool
    {
        if (strlen($hex) < 16 || !ctype_xdigit($hex)) {
            return false;
        }

        return self::calculate($hex) >= $threshold;
    }

    /**
     * Check if a base64 string exhibits high entropy (typical random b64 >= 4.2).
     */
    public static function isHighEntropyBase64(string $b64, float $threshold = 4.2): bool
    {
        if (strlen($b64) < 16) {
            return false;
        }

        return self::calculate($b64) >= $threshold;
    }
}
