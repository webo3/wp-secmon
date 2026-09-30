<?php
/**
 * Build the single-file distribution:
 *
 *   php -d phar.readonly=0 build.php
 *
 * Writes dist/wp-secmon.phar and dist/wp-secmon.phar.sha256. Install it on a server
 * with: php wp-secmon.phar install
 */

declare(strict_types=1);

if (!class_exists('Phar')) {
    fwrite(STDERR, "the phar extension is required\n");
    exit(1);
}
if (ini_get('phar.readonly')) {
    fwrite(STDERR, "phar.readonly is on; run: php -d phar.readonly=0 build.php\n");
    exit(1);
}

$root = __DIR__;
$out = "$root/dist/wp-secmon.phar";
if (!is_dir(dirname($out))) {
    mkdir(dirname($out), 0755, true);
}
foreach ([$out, "$out.sha256"] as $file) {
    if (is_file($file)) {
        unlink($file);
    }
}

$files = [];
foreach (['src', 'resources'] as $dir) {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("$root/$dir", FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $files[] = substr($file->getPathname(), strlen($root) + 1);
    }
}
$files[] = 'LICENSE';
sort($files);

$phar = new Phar($out, 0, 'wp-secmon.phar');
$phar->startBuffering();
foreach ($files as $file) {
    $phar->addFile("$root/$file", $file);
}
$phar->setStub(<<<'STUB'
#!/usr/bin/env php
<?php
Phar::mapPhar('wp-secmon.phar');
require 'phar://wp-secmon.phar/src/main.php';
__HALT_COMPILER();
STUB);
$phar->setSignatureAlgorithm(Phar::SHA256);
$phar->stopBuffering();
unset($phar);
chmod($out, 0755);

$hash = hash_file('sha256', $out);
file_put_contents("$out.sha256", "$hash  wp-secmon.phar\n");
preg_match("/const VERSION = '([^']+)'/", (string) file_get_contents("$root/src/bootstrap.php"), $m);
printf("built dist/wp-secmon.phar %s (%d files, %d KB)\nsha256 %s\n", $m[1] ?? '?', count($files), filesize($out) / 1024, $hash);
