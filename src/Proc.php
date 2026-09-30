<?php

declare(strict_types=1);

namespace WpSecMon;

/**
 * Process execution without a shell (proc_open with an argument array).
 *
 * Output always goes to files, never pipes: a process left behind by site code
 * could otherwise keep a pipe open and hang wp-secmon. The timeout is enforced
 * here as well, as a backstop to timeout(1).
 */
final class Proc
{
    public const TIMEOUT = 124;

    /**
     * Run $cmd, writing stdout/stderr to the given files. Returns the exit code
     * (128+N when killed by signal N, 124 on timeout, 127 if it could not start).
     */
    public static function run(array $cmd, string $stdout, string $stderr, int $timeout, ?array $env = null, ?string $stdin = null): int
    {
        $spec = [
            0 => $stdin === null ? ['file', '/dev/null', 'r'] : ['pipe', 'r'],
            1 => ['file', $stdout, 'w'],
            2 => ['file', $stderr, 'w'],
        ];
        $env = $env ?? ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL' => 'C'];
        $proc = @proc_open($cmd, $spec, $pipes, '/', $env);
        if (!is_resource($proc)) {
            @file_put_contents($stderr, 'cannot start ' . $cmd[0] . "\n", FILE_APPEND);
            return 127;
        }
        if ($stdin !== null) {
            @fwrite($pipes[0], $stdin);
            fclose($pipes[0]);
        }

        $deadline = microtime(true) + max(1, $timeout);
        $sleep = 10000;
        $code = -1;
        while (true) {
            $st = proc_get_status($proc);
            if (!$st['running']) {
                $code = $st['signaled'] ? 128 + $st['termsig'] : $st['exitcode'];
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($proc, 15);
                usleep(2000000);
                if (proc_get_status($proc)['running']) {
                    proc_terminate($proc, 9);
                }
                $code = self::TIMEOUT;
                break;
            }
            usleep($sleep);
            $sleep = min($sleep * 2, 200000);
        }
        proc_close($proc);
        return $code;
    }

    /** Run a trusted root-side command and return [exit code, stdout, stderr]. */
    public static function capture(array $cmd, int $timeout = 60, ?string $stdin = null): array
    {
        $out = tempnam(sys_get_temp_dir(), 'wpg');
        $err = tempnam(sys_get_temp_dir(), 'wpg');
        try {
            $code = self::run($cmd, $out, $err, $timeout, null, $stdin);
            return [$code, (string) @file_get_contents($out), (string) @file_get_contents($err)];
        } finally {
            @unlink($out);
            @unlink($err);
        }
    }
}
