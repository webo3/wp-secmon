<?php
/**
 * wp-secmon bootstrap: autoloader and error handling.
 *
 * Requires PHP 7.4+ (proc_open() with an argument array, so commands never go
 * through a shell).
 */

declare(strict_types=1);

namespace WpSecMon;

const VERSION = '0.3.2';

spl_autoload_register(static function (string $class): void {
    $prefix = __NAMESPACE__ . '\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
ini_set('log_errors', '0');
ini_set('memory_limit', '1024M');

// Turn PHP warnings into exceptions; expected failures use @ and are checked.
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    if (!(error_reporting() & $no)) {
        return false;
    }
    throw new \ErrorException($msg, 0, $no, $file, $line);
});
