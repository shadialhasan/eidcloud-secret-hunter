<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter;

use EidCloud\SecretHunter\Models\Finding;
use EidCloud\SecretHunter\Models\ScanResult;
use EidCloud\SecretHunter\Rules\RuleRegistry;
use EidCloud\SecretHunter\Rules\Severity;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * High-velocity secrets, tokens, and credential detection scanner.
 */
class Scanner
{
    private RuleRegistry $registry;

    /** @var string[] */
    private array $defaultIgnoredDirs = [
        '.git',
        'vendor',
        'node_modules',
        'dist',
        'build',
        '.idea',
        '.vscode',
        '.gradle',
        'cache',
        '.system_generated',
    ];

    /** @var string[] */
    private array $defaultIgnoredExtensions = [
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'ico',
        'mp3', 'mp4', 'avi', 'mov', 'wav',
        'zip', 'tar', 'gz', 'bz2', '7z', 'rar',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'exe', 'dll', 'so', 'dylib', 'bin', 'iso',
        'woff', 'woff2', 'ttf', 'eot', 'otf',
        'lock',
    ];

    public function __construct(?RuleRegistry $registry = null)
    {
        $this->registry = $registry ?? RuleRegistry::create();
    }

    public function getRegistry(): RuleRegistry
    {
        return $this->registry;
    }

    /**
     * Scan an entire directory recursively.
     *
     * @param string $path Path to directory
     * @param array{
     *     minSeverity?: string,
     *     mask?: bool,
     *     ignorePaths?: string[],
     *     extensions?: string[],
     *     maxFileSize?: int,
     * } $options
     */
    public function scanDirectory(string $path, array $options = []): ScanResult
    {
        $startTime = microtime(true);
        $realPath = realpath($path);

        if ($realPath === false || !is_dir($realPath)) {
            throw new \InvalidArgumentException("Target path is not a valid directory: {$path}");
        }

        $scanResult = new ScanResult([], $realPath);
        $minSeverity = $options['minSeverity'] ?? Severity::LOW;
        $maxFileSize = $options['maxFileSize'] ?? (10 * 1024 * 1024); // 10 MB max

        $ignoredDirs = array_merge($this->defaultIgnoredDirs, $options['ignorePaths'] ?? []);

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($realPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            /** @var SplFileInfo $item */
            $filePath = $item->getPathname();
            $subPath = substr($filePath, strlen($realPath) + 1);

            // Check if within ignored directory
            foreach ($ignoredDirs as $ignored) {
                if ($this->pathContainsDir($subPath, $ignored)) {
                    continue 2;
                }
            }

            if ($item->isDir()) {
                continue;
            }

            // Check file extension
            $ext = strtolower($item->getExtension());
            if (in_array($ext, $this->defaultIgnoredExtensions, true)) {
                continue;
            }

            if (!empty($options['extensions']) && !in_array($ext, $options['extensions'], true)) {
                continue;
            }

            // Check file size
            if ($item->getSize() > $maxFileSize) {
                continue;
            }

            // Check if binary file
            if ($this->isBinaryFile($filePath)) {
                continue;
            }

            $fileFindings = $this->scanFileInternal($filePath, $subPath, $minSeverity);
            $scanResult->scannedFilesCount++;
            $scanResult->scannedLinesCount += $fileFindings['linesCount'];

            foreach ($fileFindings['findings'] as $finding) {
                $scanResult->addFinding($finding);
            }
        }

        $scanResult->duration = microtime(true) - $startTime;
        return $scanResult;
    }

    /**
     * Scan a single file.
     *
     * @return Finding[]
     */
    public function scanFile(string $filePath, array $options = []): array
    {
        $realPath = realpath($filePath);
        if ($realPath === false || !is_file($realPath)) {
            throw new \InvalidArgumentException("Target is not a valid file: {$filePath}");
        }

        if ($this->isBinaryFile($realPath)) {
            return [];
        }

        $minSeverity = $options['minSeverity'] ?? Severity::LOW;
        $res = $this->scanFileInternal($realPath, basename($realPath), $minSeverity);
        return $res['findings'];
    }

    /**
     * Scan raw text string line by line.
     *
     * @return Finding[]
     */
    public function scanString(string $content, string $virtualFilename = 'inline', string $minSeverity = Severity::LOW): array
    {
        $lines = explode("\n", $content);
        $findings = [];
        $rules = $this->registry->getAll();

        foreach ($lines as $lineIndex => $line) {
            $lineNumber = $lineIndex + 1;

            // Support inline ignore directives
            if (str_contains($line, 'eidcloud:ignore') || str_contains($line, 'nosecret')) {
                continue;
            }

            foreach ($rules as $rule) {
                if (!Severity::isAtLeast($rule->severity, $minSeverity)) {
                    continue;
                }

                $matches = $rule->matchLine($line);
                foreach ($matches as $match) {
                    $rawSecret = $match['secret'];
                    $offset = $match['offset'];

                    $findings[] = new Finding(
                        ruleId: $rule->id,
                        ruleName: $rule->name,
                        severity: $rule->severity,
                        category: $rule->category,
                        file: $virtualFilename,
                        line: $lineNumber,
                        column: $offset + 1,
                        rawSecret: $rawSecret,
                        snippet: trim($line)
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * @return array{findings: Finding[], linesCount: int}
     */
    private function scanFileInternal(string $absolutePath, string $relativePath, string $minSeverity): array
    {
        $content = @file_get_contents($absolutePath);
        if ($content === false) {
            return ['findings' => [], 'linesCount' => 0];
        }

        $lines = explode("\n", $content);
        $linesCount = count($lines);
        $findings = [];
        $rules = $this->registry->getAll();

        foreach ($lines as $lineIndex => $line) {
            $lineNumber = $lineIndex + 1;

            if (str_contains($line, 'eidcloud:ignore') || str_contains($line, 'nosecret')) {
                continue;
            }

            foreach ($rules as $rule) {
                if (!Severity::isAtLeast($rule->severity, $minSeverity)) {
                    continue;
                }

                $matches = $rule->matchLine($line);
                foreach ($matches as $match) {
                    $rawSecret = $match['secret'];
                    $offset = $match['offset'];

                    $findings[] = new Finding(
                        ruleId: $rule->id,
                        ruleName: $rule->name,
                        severity: $rule->severity,
                        category: $rule->category,
                        file: $relativePath,
                        line: $lineNumber,
                        column: $offset + 1,
                        rawSecret: $rawSecret,
                        snippet: trim($line)
                    );
                }
            }
        }

        return [
            'findings'   => $findings,
            'linesCount' => $linesCount,
        ];
    }

    private function isBinaryFile(string $filePath): bool
    {
        $handle = @fopen($filePath, 'rb');
        if (!$handle) {
            return true;
        }

        $chunk = fread($handle, 1024);
        fclose($handle);

        if ($chunk === false || strlen($chunk) === 0) {
            return false;
        }

        return str_contains($chunk, "\0");
    }

    private function pathContainsDir(string $path, string $dirName): bool
    {
        $normalized = str_replace('\\', '/', $path);
        $parts = explode('/', trim($normalized, '/'));
        return in_array($dirName, $parts, true);
    }
}
