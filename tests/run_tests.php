<?php

declare(strict_types=1);

/**
 * eidcloud-secret-hunter - Zero-Dependency Automated Test Runner
 *
 * @author Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
 * @license MIT
 */

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/SecretHunterTest.php';

use EidCloud\SecretHunter\Tests\SecretHunterTest;

$start = microtime(true);
$testClass = new SecretHunterTest();
$reflection = new ReflectionClass($testClass);
$methods = $reflection->getMethods(ReflectionMethod::IS_PUBLIC);

$testMethods = array_filter(
    $methods,
    static fn (ReflectionMethod $m) => str_starts_with($m->getName(), 'test')
);

$total = count($testMethods);
$passed = 0;
$failed = 0;
$failures = [];

echo "\n";
echo "╔════════════════════════════════════════════════════════════════════╗\n";
echo "║            🛡️  eidcloud-secret-hunter Automated Test Suite        ║\n";
echo "╚════════════════════════════════════════════════════════════════════╝\n";
echo "Running {$total} tests on PHP " . PHP_VERSION . "...\n\n";

foreach ($testMethods as $method) {
    $methodName = $method->getName();
    $testStart = microtime(true);

    try {
        $method->invoke($testClass);
        $testElapsed = (microtime(true) - $testStart) * 1000;
        printf("  \033[32m✔ PASS\033[0m  %-42s (%.2f ms)\n", $methodName, $testElapsed);
        $passed++;
    } catch (\Throwable $e) {
        $testElapsed = (microtime(true) - $testStart) * 1000;
        printf("  \033[31m✖ FAIL\033[0m  %-42s (%.2f ms)\n", $methodName, $testElapsed);
        $failed++;
        $failures[] = [
            'method'  => $methodName,
            'message' => $e->getMessage(),
            'file'    => $e->getFile(),
            'line'    => $e->getLine(),
        ];
    }
}

$elapsed = microtime(true) - $start;

echo "\n" . str_repeat('─', 70) . "\n";
if ($failed === 0) {
    printf(
        "\033[32;1mTEST SUITE PASSED!\033[0m All %d tests executed successfully in %.4f seconds.\n",
        $passed,
        $elapsed
    );
    echo str_repeat('─', 70) . "\n\n";
    exit(0);
} else {
    printf(
        "\033[31;1mTEST SUITE FAILED!\033[0m %d passed, %d failed in %.4f seconds.\n",
        $passed,
        $failed,
        $elapsed
    );
    echo "\nFailures:\n";
    foreach ($failures as $f) {
        echo "  - {$f['method']}: {$f['message']} ({$f['file']}:{$f['line']})\n";
    }
    echo str_repeat('─', 70) . "\n\n";
    exit(1);
}
