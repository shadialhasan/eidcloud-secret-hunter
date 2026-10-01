<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Models;

use EidCloud\SecretHunter\Rules\Severity;

/**
 * Encapsulates the results of a scanning run.
 */
class ScanResult
{
    /** @var Finding[] */
    private array $findings = [];

    public int $scannedFilesCount = 0;
    public int $scannedLinesCount = 0;
    public float $duration = 0.0;
    public ?string $targetPath = null;

    /**
     * @param Finding[] $findings
     */
    public function __construct(array $findings = [], ?string $targetPath = null)
    {
        $this->targetPath = $targetPath;
        foreach ($findings as $finding) {
            $this->addFinding($finding);
        }
    }

    public function addFinding(Finding $finding): void
    {
        $this->findings[] = $finding;
    }

    /**
     * @return Finding[]
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    public function totalFindings(): int
    {
        return count($this->findings);
    }

    public function hasFindings(): bool
    {
        return !empty($this->findings);
    }

    public function hasCriticalOrHigh(): bool
    {
        return $this->hasViolations(Severity::HIGH);
    }

    public function hasViolations(string $minSeverity = Severity::HIGH): bool
    {
        foreach ($this->findings as $finding) {
            if (Severity::isAtLeast($finding->severity, $minSeverity)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return counts grouped by severity: ['critical' => 2, 'high' => 5, ...]
     */
    public function countBySeverity(): array
    {
        $counts = [
            Severity::CRITICAL => 0,
            Severity::HIGH     => 0,
            Severity::MEDIUM   => 0,
            Severity::LOW      => 0,
            Severity::INFO     => 0,
        ];

        foreach ($this->findings as $finding) {
            $sev = strtolower($finding->severity);
            if (isset($counts[$sev])) {
                $counts[$sev]++;
            } else {
                $counts[$sev] = 1;
            }
        }

        return $counts;
    }

    /**
     * Filter findings by minimum severity level.
     *
     * @return Finding[]
     */
    public function getFilteredFindings(string $minSeverity = Severity::LOW): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (Finding $f) => Severity::isAtLeast($f->severity, $minSeverity)
        ));
    }

    public function toArray(bool $mask = true, string $minSeverity = Severity::LOW): array
    {
        $filtered = $this->getFilteredFindings($minSeverity);
        $findingsArray = array_map(static fn (Finding $f) => $f->toArray($mask), $filtered);

        return [
            'summary' => [
                'target'        => $this->targetPath,
                'scanned_files' => $this->scannedFilesCount,
                'scanned_lines' => $this->scannedLinesCount,
                'total_secrets' => count($filtered),
                'by_severity'   => $this->countBySeverity(),
                'duration_sec'  => round($this->duration, 4),
                'clean'         => count($filtered) === 0,
            ],
            'findings' => $findingsArray,
        ];
    }
}
