<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Rules;

/**
 * Secret Severity levels and comparison helpers.
 */
final class Severity
{
    public const CRITICAL = 'critical';
    public const HIGH     = 'high';
    public const MEDIUM   = 'medium';
    public const LOW      = 'low';
    public const INFO     = 'info';

    private const RANKS = [
        self::INFO     => 0,
        self::LOW      => 1,
        self::MEDIUM   => 2,
        self::HIGH     => 3,
        self::CRITICAL => 4,
    ];

    public static function all(): array
    {
        return [
            self::CRITICAL,
            self::HIGH,
            self::MEDIUM,
            self::LOW,
            self::INFO,
        ];
    }

    public static function isValid(string $severity): bool
    {
        return isset(self::RANKS[strtolower($severity)]);
    }

    public static function rank(string $severity): int
    {
        return self::RANKS[strtolower($severity)] ?? 0;
    }

    public static function isAtLeast(string $severity, string $threshold): bool
    {
        return self::rank($severity) >= self::rank($threshold);
    }
}
