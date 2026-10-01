<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Report;

use EidCloud\SecretHunter\Models\ScanResult;
use EidCloud\SecretHunter\Rules\Severity;

/**
 * Renders ScanResult in structured JSON format for CI/CD integrations.
 */
class JsonReporter
{
    public static function render(ScanResult $result, bool $mask = true, string $minSeverity = Severity::LOW): string
    {
        $data = $result->toArray($mask, $minSeverity);
        return (string)json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
