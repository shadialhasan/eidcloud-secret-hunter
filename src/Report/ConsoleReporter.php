<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Report;

use EidCloud\SecretHunter\Models\Finding;
use EidCloud\SecretHunter\Models\ScanResult;
use EidCloud\SecretHunter\Rules\Severity;

/**
 * Console and terminal reporter with color badges, formatting, and CI output.
 */
class ConsoleReporter
{
    private bool $useColors;

    public function __construct(?bool $useColors = null)
    {
        $this->useColors = $useColors ?? $this->supportsColors();
    }

    public function render(ScanResult $result, bool $mask = true, string $minSeverity = Severity::LOW): string
    {
        $filtered = $result->getFilteredFindings($minSeverity);
        $lines = [];

        $lines[] = $this->renderBanner();

        if (empty($filtered)) {
            $lines[] = $this->color("  [✓] All scanned files are CLEAN. No secrets detected!", 'green');
            $lines[] = "";
        } else {
            $lines[] = $this->color(sprintf("  Found %d potential secret(s):", count($filtered)), 'bold');
            $lines[] = "";

            foreach ($filtered as $i => $finding) {
                $lines[] = $this->renderFinding($i + 1, $finding, $mask);
            }
        }

        $lines[] = $this->renderSummary($result, $filtered, $minSeverity);
        return implode("\n", $lines) . "\n";
    }

    private function renderBanner(): string
    {
        $banner = [
            $this->color("╔════════════════════════════════════════════════════════════════════╗", 'cyan'),
            $this->color("║                 🛡️  eidcloud-secret-hunter v1.0.0                 ║", 'cyan'),
            $this->color("║        High-Velocity Secrets & Credential Detection Scanner        ║", 'cyan'),
            $this->color("╚════════════════════════════════════════════════════════════════════╝", 'cyan'),
            "",
        ];
        return implode("\n", $banner);
    }

    private function renderFinding(int $index, Finding $finding, bool $mask): string
    {
        $badge = $this->renderSeverityBadge($finding->severity);
        $secretValue = $mask ? $finding->maskedSecret : $finding->rawSecret;

        $out = [];
        $out[] = sprintf("  #%d %s %s [%s]", $index, $badge, $this->color($finding->ruleName, 'bold'), $this->color($finding->category, 'dim'));
        $out[] = sprintf("     %s %s:%d:%d", $this->color("Location:", 'dim'), $finding->file, $finding->line, $finding->column);
        $out[] = sprintf("     %s   %s (Entropy: %.2f)", $this->color("Secret:", 'dim'), $this->color($secretValue, 'yellow'), $finding->entropy);

        if (!empty($finding->snippet)) {
            $out[] = sprintf("     %s  %s", $this->color("Snippet:", 'dim'), $this->color($finding->snippet, 'dim'));
        }

        if ($finding->commitHash !== null) {
            $out[] = sprintf("     %s   %s by %s on %s",
                $this->color("Commit:", 'dim'),
                substr($finding->commitHash, 0, 8),
                $finding->commitAuthor ?? 'unknown',
                $finding->commitDate ?? 'unknown'
            );
        }

        $out[] = "";
        return implode("\n", $out);
    }

    private function renderSeverityBadge(string $severity): string
    {
        return match (strtolower($severity)) {
            Severity::CRITICAL => $this->color(" CRITICAL ", 'bg_red'),
            Severity::HIGH     => $this->color("   HIGH   ", 'bg_yellow'),
            Severity::MEDIUM   => $this->color("  MEDIUM  ", 'bg_blue'),
            Severity::LOW      => $this->color("   LOW    ", 'bg_gray'),
            default            => $this->color("   INFO   ", 'dim'),
        };
    }

    /**
     * @param Finding[] $filtered
     */
    private function renderSummary(ScanResult $result, array $filtered, string $minSeverity): string
    {
        $counts = $result->countBySeverity();
        $isClean = empty($filtered);

        $out = [];
        $out[] = $this->color("─── Scan Summary ────────────────────────────────────────────────────", 'dim');
        $out[] = sprintf("  Target:         %s", $result->targetPath ?? 'Current working tree');
        $out[] = sprintf("  Files Scanned:  %d", $result->scannedFilesCount);
        $out[] = sprintf("  Lines Analyzed: %s", number_format($result->scannedLinesCount));
        $out[] = sprintf("  Duration:       %.3f seconds", $result->duration);
        $out[] = "";
        $out[] = sprintf(
            "  Breakdown:      %s Critical | %s High | %s Medium | %s Low",
            $this->color((string)$counts[Severity::CRITICAL], $counts[Severity::CRITICAL] > 0 ? 'red' : 'dim'),
            $this->color((string)$counts[Severity::HIGH], $counts[Severity::HIGH] > 0 ? 'yellow' : 'dim'),
            $this->color((string)$counts[Severity::MEDIUM], $counts[Severity::MEDIUM] > 0 ? 'blue' : 'dim'),
            $this->color((string)$counts[Severity::LOW], 'dim')
        );
        $out[] = $this->color("─────────────────────────────────────────────────────────────────────", 'dim');

        if ($isClean) {
            $out[] = $this->color("  RESULT: [PASSED] Clean codebase - no secrets found.", 'green');
        } else {
            $hasBlockingViolations = $result->hasViolations($minSeverity);
            if ($hasBlockingViolations) {
                $out[] = $this->color("  RESULT: [FAILED] Action required! Violations meeting or exceeding threshold found.", 'red');
            } else {
                $out[] = $this->color("  RESULT: [WARNING] Minor secrets found below blocker threshold.", 'yellow');
            }
        }

        return implode("\n", $out);
    }

    private function color(string $text, string $style): string
    {
        if (!$this->useColors) {
            return $text;
        }

        $codes = [
            'bold'      => "\033[1m",
            'dim'       => "\033[2m",
            'red'       => "\033[31m",
            'green'     => "\033[32m",
            'yellow'    => "\033[33m",
            'blue'      => "\033[34m",
            'cyan'      => "\033[36m",
            'bg_red'    => "\033[41;97;1m",
            'bg_yellow' => "\033[43;30;1m",
            'bg_blue'   => "\033[44;97;1m",
            'bg_gray'   => "\033[100;97m",
        ];

        $code = $codes[$style] ?? '';
        return $code !== '' ? "{$code}{$text}\033[0m" : $text;
    }

    private function supportsColors(): bool
    {
        if (getenv('NO_COLOR') !== false) {
            return false;
        }

        if (PHP_OS_FAMILY === 'Windows') {
            return (getenv('ANSICON') !== false
                || getenv('ConEmuANSI') === 'ON'
                || getenv('TERM') === 'xterm'
                || (function_exists('sapi_windows_vt100_support') && @sapi_windows_vt100_support(STDOUT)));
        }

        return function_exists('posix_isatty') && @posix_isatty(STDOUT);
    }
}
