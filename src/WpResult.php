<?php

declare(strict_types=1);

namespace WpSecMon;

final class WpResult
{
    /**
     * Lines of output accepted per stream. Parsing splits output into lines;
     * millions of tiny lines would exhaust memory and abort the whole run
     * before the report is sent.
     */
    private const MAX_LINES = 200000;

    public int $code;
    public string $stdout;
    public string $stderr;

    public function __construct(int $code, string $stdout, string $stderr)
    {
        $this->code = $code;
        $this->stdout = self::plain($stdout);
        $this->stderr = self::plain($stderr);
    }

    /**
     * Result of a command run by RunAs: reads its output files (at most $max
     * bytes each) and deletes them. More output than that, or more than
     * MAX_LINES lines, fails with RunAs::TOO_MUCH_OUTPUT.
     */
    public static function fromFiles(int $code, string $stdout, string $stderr, int $max): self
    {
        $read = static function (string $file) use ($max, &$code): string {
            $size = (int) @filesize($file);
            $data = (string) @file_get_contents($file, false, null, 0, $max);
            @unlink($file);
            if ($size >= $max || substr_count($data, "\n") > self::MAX_LINES) {
                $code = RunAs::TOO_MUCH_OUTPUT;
                return '';
            }
            return $data;
        };
        $out = $read($stdout);
        $err = $read($stderr);
        return new self($code, $out, $err);
    }

    /** Drop ANSI color sequences. */
    private static function plain(string $s): string
    {
        return (string) preg_replace('/\e\[[0-9;]*[A-Za-z]/', '', $s);
    }

    public function ok(): bool
    {
        return $this->code === 0;
    }

    public function json(string $prefix = ''): ?array
    {
        return Util::jsonLine($this->stdout, $prefix);
    }

    /** Short reason for a failure, e.g. "Error establishing a database connection". */
    public function reason(): string
    {
        if ($this->code === Proc::TIMEOUT) {
            return I18n::t('timed out');
        }
        if ($this->code === RunAs::REFUSED) {
            return trim(Util::oneLine($this->stderr)) ?: I18n::t('refused to run');
        }
        if ($this->code === RunAs::TOO_MUCH_OUTPUT) {
            return I18n::t('too much output (see max_output_mb)');
        }
        foreach (array_reverse(preg_split('/\R/', $this->stderr . "\n" . $this->stdout) ?: []) as $line) {
            if (preg_match('/^(?:Error|PHP Fatal error|Fatal error):\s*(.+)$/', trim($line), $m)) {
                return Util::oneLine(strip_tags($m[1]), 200);
            }
        }
        return I18n::t('exit code %d', $this->code);
    }

    public function details(): string
    {
        return Util::tail($this->stderr . "\n" . $this->stdout, 6);
    }
}
