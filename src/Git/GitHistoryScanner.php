<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Git;

use EidCloud\SecretHunter\Models\Finding;
use EidCloud\SecretHunter\Models\ScanResult;
use EidCloud\SecretHunter\Rules\RuleRegistry;
use EidCloud\SecretHunter\Rules\Severity;

/**
 * Git commit history scanner that scans commit diffs for leaked,
 * historical, and previously deleted secrets across all commits.
 */
class GitHistoryScanner
{
    private RuleRegistry $registry;

    public function __construct(?RuleRegistry $registry = null)
    {
        $this->registry = $registry ?? RuleRegistry::create();
    }

    /**
     * Scan git history commits and their diffs.
     *
     * @param string $repoPath Root repository path
     * @param int $depth Maximum commit history depth to scan (0 for all commits)
     * @param string $minSeverity Minimum severity threshold
     * @return ScanResult
     */
    public function scanHistory(string $repoPath, int $depth = 100, string $minSeverity = Severity::LOW): ScanResult
    {
        $startTime = microtime(true);
        $realRepoPath = realpath($repoPath);

        if ($realRepoPath === false || !is_dir($realRepoPath)) {
            throw new \InvalidArgumentException("Invalid repository path: {$repoPath}");
        }

        // Verify git repository
        if (!is_dir($realRepoPath . DIRECTORY_SEPARATOR . '.git')) {
            throw new \RuntimeException("Directory is not a Git repository: {$realRepoPath}");
        }

        $depthArg = $depth > 0 ? "-n " . (int)$depth : "--all";
        $cmd = sprintf(
            'git -C %s log -p --full-history --no-color %s',
            escapeshellarg($realRepoPath),
            $depthArg
        );

        $output = [];
        $returnCode = 0;
        exec($cmd . ' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new \RuntimeException("Failed to execute git log command. Code {$returnCode}: " . implode("\n", array_slice($output, 0, 5)));
        }

        $scanResult = new ScanResult([], $realRepoPath);
        $rules = $this->registry->getAll();

        $currentCommit = null;
        $currentAuthor = null;
        $currentDate = null;
        $currentFile = null;
        $currentLineNum = 0;
        $seenFiles = [];

        foreach ($output as $line) {
            $scanResult->scannedLinesCount++;

            // Detect commit header
            if (preg_match('/^commit\s+([0-9a-f]{7,40})/i', $line, $m)) {
                $currentCommit = $m[1];
                $currentFile = null;
                $currentLineNum = 0;
                continue;
            }

            // Detect Author
            if (preg_match('/^Author:\s+(.+)$/i', $line, $m)) {
                $currentAuthor = trim($m[1]);
                continue;
            }

            // Detect Date
            if (preg_match('/^Date:\s+(.+)$/i', $line, $m)) {
                $currentDate = trim($m[1]);
                continue;
            }

            // Detect diff file target: diff --git a/path b/path
            if (preg_match('/^diff --git a\/.+ b\/(.+)$/', $line, $m)) {
                $currentFile = trim($m[1]);
                $seenFiles[$currentFile] = true;
                continue;
            }

            // Detect hunk header: @@ -10,5 +20,6 @@
            if (preg_match('/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/', $line, $m)) {
                $currentLineNum = (int)$m[1] - 1;
                continue;
            }

            // Only examine added lines (starting with '+', not '+++')
            if (str_starts_with($line, '+') && !str_starts_with($line, '+++')) {
                $currentLineNum++;
                $code = substr($line, 1);

                // Ignore ignore comments
                if (str_contains($code, 'eidcloud:ignore') || str_contains($code, 'nosecret')) {
                    continue;
                }

                foreach ($rules as $rule) {
                    if (!Severity::isAtLeast($rule->severity, $minSeverity)) {
                        continue;
                    }

                    $matches = $rule->matchLine($code);
                    foreach ($matches as $match) {
                        $rawSecret = $match['secret'];
                        $offset = $match['offset'];

                        $scanResult->addFinding(new Finding(
                            ruleId: $rule->id,
                            ruleName: $rule->name,
                            severity: $rule->severity,
                            category: $rule->category,
                            file: $currentFile ?? 'git-diff',
                            line: $currentLineNum,
                            column: $offset + 1,
                            rawSecret: $rawSecret,
                            snippet: trim($code),
                            commitHash: $currentCommit,
                            commitAuthor: $currentAuthor,
                            commitDate: $currentDate
                        ));
                    }
                }
            } elseif (str_starts_with($line, ' ')) {
                $currentLineNum++;
            }
        }

        $scanResult->scannedFilesCount = count($seenFiles);
        $scanResult->duration = microtime(true) - $startTime;

        return $scanResult;
    }
}
