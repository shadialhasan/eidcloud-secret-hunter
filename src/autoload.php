<?php

declare(strict_types=1);

/**
 * eidcloud-secret-hunter - Standalone PSR-4 Autoloader
 *
 * Allows running the scanner without external vendor dependencies.
 *
 * @author Eng. MHD. Shadi AL-Hasan <mhd.shadi.alhasan@gmail.com>
 * @license MIT
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'EidCloud\\SecretHunter\\';
    $baseDir = __DIR__ . DIRECTORY_SEPARATOR;

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', DIRECTORY_SEPARATOR, $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});
