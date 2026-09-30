<?php
/**
 * wp-secmon entry point, shared by the phar stub and bin/wp-secmon.
 *
 * Keep this file parseable by old PHP versions so they get a clear message.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}
if (PHP_VERSION_ID < 70400) {
    fwrite(STDERR, 'wp-secmon needs PHP 7.4 or later (this is ' . PHP_VERSION . ")\n");
    exit(1);
}

require __DIR__ . '/bootstrap.php';

exit(\WpSecMon\Cli::main($_SERVER['argv']));
