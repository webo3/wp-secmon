<?php
/**
 * Unit tests for the parsing and comparison logic. Run: php tests/unit.php
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use WpSecMon\Alerts;
use WpSecMon\Check\ChecksumsCheck;
use WpSecMon\Check\IntegrityCheck;
use WpSecMon\Check\UsersCheck;
use WpSecMon\Check\VulnsCheck;
use WpSecMon\Config;
use WpSecMon\Http;
use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Report;
use WpSecMon\RunAs;
use WpSecMon\Sites;
use WpSecMon\Updater;
use WpSecMon\Util;
use WpSecMon\VulnDb;
use WpSecMon\WpResult;

$failures = 0;
$count = 0;

function ok(string $name, bool $cond, $info = null): void
{
    global $failures, $count;
    $count++;
    if ($cond) {
        return;
    }
    $failures++;
    fwrite(STDOUT, "FAIL: $name\n" . ($info !== null ? '      ' . var_export($info, true) . "\n" : ''));
}

function titles(array $events): array
{
    return array_map(static function ($e) {
        return $e[0] . ': ' . $e[1];
    }, $events);
}

/**
 * Messages passed to I18n::t(), tc(), n() and date() in the PHP files under $dir.
 * @return array{0: array<string, ?string>, 1: string[]} [catalog key => plural form (null: not plural), problems]
 */
function i18nMessages(string $dir): array
{
    $messages = [];
    $problems = [];
    $literal = static function (array $tokens): ?string {
        $src = '';
        foreach ($tokens as $tok) {
            if (is_array($tok) && in_array($tok[0], [T_CONSTANT_ENCAPSED_STRING, T_START_HEREDOC, T_ENCAPSED_AND_WHITESPACE, T_END_HEREDOC], true)) {
                $src .= $tok[1];
            } elseif ($tok === '.') {
                $src .= ' . ';
            } else {
                return null;
            }
        }
        return $src === '' ? null : eval("return $src;");
    };
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }
        // I18n itself translates variables (formats, month names): only its literal messages count.
        $self = $file->getFilename() === 'I18n.php';
        $t = array_values(array_filter(token_get_all((string) file_get_contents($file->getPathname())), static function ($tok) {
            return !is_array($tok) || !in_array($tok[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
        }));
        for ($i = 0; $i < count($t) - 3; $i++) {
            $class = is_array($t[$i]) ? $t[$i][1] : '';
            if (!($class === 'I18n' || ($self && $class === 'self')) || !is_array($t[$i + 1]) || $t[$i + 1][0] !== T_DOUBLE_COLON
                || !is_array($t[$i + 2]) || !in_array($t[$i + 2][1], ['t', 'tc', 'n', 'date'], true) || ($t[$i + 3] ?? '') !== '(') {
                continue;
            }
            // Arguments, split on the commas outside brackets.
            $args = [[]];
            $depth = 0;
            for ($j = $i + 4; $j < count($t); $j++) {
                $text = is_array($t[$j]) ? $t[$j][1] : $t[$j];
                if ($depth === 0 && ($text === ')' || $text === ',')) {
                    if ($text === ')') {
                        break;
                    }
                    $args[] = [];
                    continue;
                }
                if (in_array($text, ['(', '[', '{'], true) || (is_array($t[$j]) && in_array($t[$j][0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
                    $depth++;
                } elseif (in_array($text, [')', ']', '}'], true)) {
                    $depth--;
                }
                $args[count($args) - 1][] = $t[$j];
            }
            $method = $t[$i + 2][1];
            $where = $file->getFilename() . ':' . $t[$i][2];
            if ($method === 'n') {
                [$one, $many] = [$literal($args[1] ?? []), $literal($args[2] ?? [])];
                if ($one !== null && $many !== null) {
                    $messages[$one] = $many;
                } elseif (!$self) {
                    $problems[] = "$where: I18n::n() needs literal messages";
                }
            } elseif ($method === 'tc') {
                [$context, $message] = [$literal($args[0]), $literal($args[1] ?? [])];
                if ($context !== null && $message !== null) {
                    $messages["$context\x04$message"] = null;
                } elseif (!$self) {
                    $problems[] = "$where: I18n::tc() needs a literal context and message";
                }
            } elseif (($message = $literal($args[0])) !== null) {
                $messages[$message] = $messages[$message] ?? null;
            } elseif (!$self) {
                $problems[] = "$where: I18n::$method() needs a literal message";
            }
        }
    }
    return [$messages, $problems];
}

/** The sprintf() conversions of $format, sorted (translations may reorder them). */
function conversions(string $format): array
{
    preg_match_all('/%(?:\d+\$)?[-+ 0]*\d*(?:\.\d+)?([bcdeEfFgGosuxX%])/', $format, $m);
    sort($m[1]);
    return $m[1];
}

Log::$verbosity = -1;

// ---------------------------------------------------------------- Util
ok('jsonLine skips PHP notices', Util::jsonLine("Deprecated: foo in x.php on line 3\n[{\"a\":1}]\n") === [['a' => 1]]);
ok('jsonLine with prefix', Util::jsonLine("noise\nWPSECMON-JSON:{\"x\":2}\n", 'WPSECMON-JSON:') === ['x' => 2]);
ok('jsonLine none', Util::jsonLine("Error: Error establishing a database connection.\n") === null);
ok('oneLine strips escapes', Util::oneLine("a\x1b[31mb\nc") === 'a [31mb c');
ok('oneLine strips C1 controls', Util::oneLine("a\u{9b}31mb\u{e9}") === "a 31mb\u{e9}");
ok('text keeps tabs and newlines, drops C1', Util::text("a\n\u{9d}b\tc") === "a\nb\tc");
ok('matchAny star crosses slash', Util::matchAny('/home/a/mail', ['*/mail']));

// ---------------------------------------------------------------- VulnDb
$op = static function ($min, $minOp, $max, $maxOp) {
    return ['min_version' => $min, 'min_operator' => $minOp, 'max_version' => $max, 'max_operator' => $maxOp, 'unfixed' => '0'];
};
ok('affects lt below', VulnDb::affects($op(null, null, '5.3.2', 'lt'), '5.3.1'));
ok('affects lt equal', !VulnDb::affects($op(null, null, '5.3.2', 'lt'), '5.3.2'));
ok('affects le equal', VulnDb::affects($op(null, null, '5.3.2', 'le'), '5.3.2'));
ok('affects 5.10 > 5.9', !VulnDb::affects($op(null, null, '5.9', 'lt'), '5.10'));
ok('affects range', VulnDb::affects($op('2.0', 'ge', '2.5', 'le'), '2.1') && !VulnDb::affects($op('2.0', 'ge', '2.5', 'le'), '1.9'));
ok('affects gt', !VulnDb::affects($op('2.0', 'gt', null, null), '2.0'));
ok('affects core (no operator)', VulnDb::affects(null, '6.4.1'));

$api = ['error' => 0, 'data' => ['closed' => 1, 'closed_reason' => 'security-issue', 'vulnerability' => [
    ['uuid' => 'u1', 'name' => 'X < 1.2', 'operator' => $op(null, null, '1.2', 'lt'),
        'source' => [['id' => 'CVE-2024-1', 'name' => 'CVE-2024-1', 'link' => 'https://cve/1'], ['id' => 'w1', 'name' => 'X &lt;= 1.1 - SQL Injection', 'link' => 'https://wf/1']],
        'impact' => ['cvss3' => ['score' => '9.8', 'severity' => 'critical']]],
    ['uuid' => 'u2', 'name' => 'X < 3.0', 'operator' => $op(null, null, '3.0', 'lt'),
        'source' => [['id' => 'w2', 'name' => 'X <= 2.9 - XSS', 'link' => 'https://wf/2']], 'impact' => []],
    ['uuid' => 'u3', 'name' => 'X < 1.0', 'operator' => $op(null, null, '1.0', 'lt'), 'source' => [], 'impact' => []],
]]];
$m = VulnDb::match($api, 'plugin', '1.1');
ok('match count', count($m) === 2, $m);
ok('match title from source + entities', ($m[0]['title'] ?? '') === 'X <= 1.1 - SQL Injection', $m[0] ?? null);
ok('match severity and fix', ($m[0]['severity'] ?? '') === 'critical' && ($m[0]['fixed'] ?? '') === '1.2' && $m[0]['cves'] === ['CVE-2024-1']);
ok('closed reason', VulnDb::closedReason($api) === 'security-issue');
[$sev, $title] = VulnsCheck::describe('Plugin X 1.1', $m);
ok('describe severity', $sev === 'critical' && $title === 'Plugin X 1.1: 2 known vulnerabilities', [$sev, $title]);
ok('unknown slug has no vulns', VulnDb::match(['data' => ['vulnerability' => null]], 'plugin', '1.0') === []);

$releases = ['7.1.2', '7.0.6', '6.9.9', '6.4.12'];
ok('core missing point release', (VulnsCheck::coreStatus('6.4.1', $releases)[0] ?? '') === 'warning');
ok('core old major', (VulnsCheck::coreStatus('7.0.6', $releases)[0] ?? '') === 'info');
ok('core unsupported branch', strpos(VulnsCheck::coreStatus('5.0', $releases)[1] ?? '', 'no longer receives') !== false);
ok('core latest', VulnsCheck::coreStatus('7.1.2', $releases) === null);

// ---------------------------------------------------------------- users
$old = UsersCheck::normalize([
    ['ID' => 1, 'user_login' => 'admin', 'user_email' => 'a@x.com', 'roles' => 'administrator', 'user_registered' => '2020-01-01'],
    ['ID' => 2, 'user_login' => 'bob', 'user_email' => 'b@x.com', 'roles' => 'subscriber', 'user_registered' => '2020-01-01'],
    ['ID' => 3, 'user_login' => 'carl', 'user_email' => 'c@x.com', 'roles' => 'editor', 'user_registered' => '2020-01-01'],
    ['ID' => 4, 'user_login' => 'dan', 'user_email' => 'd@x.com', 'roles' => 'administrator', 'user_registered' => '2020-01-01'],
]);
$new = UsersCheck::normalize([
    ['ID' => 1, 'user_login' => 'admin', 'user_email' => 'evil@x.com', 'roles' => 'administrator', 'user_registered' => '2020-01-01'],
    ['ID' => 2, 'user_login' => 'bob', 'user_email' => 'b@x.com', 'roles' => 'subscriber,administrator', 'user_registered' => '2020-01-01'],
    ['ID' => 3, 'user_login' => 'carl', 'user_email' => 'c2@x.com', 'roles' => 'author', 'user_registered' => '2020-01-01'],
    ['ID' => 7, 'user_login' => "wp\x1b[31mhack", 'user_email' => 'h@x.com', 'roles' => 'administrator', 'user_registered' => '2026-09-25'],
    ['ID' => 8, 'user_login' => 'cust', 'user_email' => 'cu@x.com', 'roles' => 'customer', 'user_registered' => '2026-09-25'],
]);
$t = titles(UsersCheck::diff($old, $new, ['administrator'], 'all', 'warning'));
$expect = [
    'critical: Account granted privileges: bob',
    "critical: New privileged account: wp\x1b[31mhack (administrator)",
    'warning: Privileged account e-mail changed: admin',
    'warning: Privileged account deleted: dan',
    'warning: 1 new account(s) created',
    'info: 1 account(s) modified',
];
ok('users diff', $t === $expect, $t);
ok('users diff privileged-only mode', !in_array('warning: 1 new account(s) created', titles(UsersCheck::diff($old, $new, ['administrator'], 'privileged', 'warning')), true));
ok('users diff unchanged', UsersCheck::diff($old, $old, ['administrator'], 'all', 'warning') === []);
$ms = UsersCheck::normalize([['ID' => 5, 'user_login' => 'net', 'user_email' => 'n@x', 'roles' => '', 'user_registered' => '']], ['net']);
ok('super admin is privileged', UsersCheck::isPrivileged($ms[0], ['administrator']));

// ---------------------------------------------------------------- integrity
$o1 = ['siteurl' => 'https://a.com', 'home' => 'https://a.com', 'users_can_register' => '0', 'default_role' => 'subscriber', 'registration' => null];
$o2 = ['siteurl' => 'https://evil.com', 'home' => 'https://a.com', 'users_can_register' => '1', 'default_role' => 'administrator', 'registration' => null];
ok('options diff', titles(IntegrityCheck::diffOptions($o1, $o2)) === [
    'critical: Site address (siteurl) changed',
    'warning: "Anyone can register" setting changed',
    'warning: Default role for new accounts changed',
], titles(IntegrityCheck::diffOptions($o1, $o2)));
ok('risky registration', IntegrityCheck::registrationRisk($o2, ['administrator']) !== null);
ok('safe registration', IntegrityCheck::registrationRisk(['users_can_register' => '1', 'default_role' => 'subscriber'], ['administrator']) === null);
ok('multisite registration', IntegrityCheck::registrationRisk(['registration' => 'all', 'default_role' => 'editor'], ['editor']) !== null);

$c1 = ['plugins' => [['slug' => 'a', 'file' => 'a/a.php', 'name' => 'A', 'version' => '1', 'active' => true], ['slug' => 'b', 'file' => 'b/b.php', 'name' => 'B', 'version' => '1', 'active' => false]], 'themes' => []];
$c2 = ['plugins' => [['slug' => 'a', 'file' => 'a/a.php', 'name' => 'A', 'version' => '2', 'active' => false], ['slug' => 'z', 'file' => 'z/z.php', 'name' => 'Z', 'version' => '1', 'active' => true]], 'themes' => [['slug' => 't', 'name' => 'T', 'version' => '1']]];
ok('components diff', titles(IntegrityCheck::diffComponents($c1, $c2)) === [
    'warning: 1 plugin(s) installed', 'warning: 1 plugin(s) deactivated', 'info: 1 plugin(s) removed',
    'info: 1 plugin(s) changed version', 'warning: 1 theme(s) installed',
], titles(IntegrityCheck::diffComponents($c1, $c2)));

$f1 = ['wp-config.php' => ['config', 'h1'], '.htaccess' => ['server-config', 'h2'], 'wp-content/mu-plugins/x.php' => ['mu-plugin', 'h3']];
$f2 = ['wp-config.php' => ['config', 'h1b'], '.htaccess' => ['server-config', 'h2'], 'wp-content/mu-plugins/x.php' => ['mu-plugin', 'h3'],
    'wp-content/mu-plugins/evil.php' => ['mu-plugin', 'h4'], 'radio.php' => ['root-php', 'h5'], 'wp-content/.htaccess' => ['content-file', 'h6']];
ok('files diff', titles(IntegrityCheck::diffFiles($f1, $f2)) === [
    'warning: wp-config.php: 1 modified',
    'critical: Non-core PHP files in the site root: 1 added',
    'warning: PHP or configuration files directly in wp-content: 1 added',
    'critical: Must-use plugins (loaded on every request, cannot be disabled): 1 added',
], titles(IntegrityCheck::diffFiles($f1, $f2)));

// ---------------------------------------------------------------- checksums
$core = ChecksumsCheck::parseCore(<<<'TXT'
Warning: File doesn't verify against checksum: wp-includes/functions.php
Warning: File should not exist: wp-admin/shell.php
Warning: File doesn't exist: readme.html
Warning: File doesn't verify against checksum: wp-content/languages/fr_FR.mo
Error: WordPress installation doesn't verify against checksums.
TXT, ['wp-content/languages/*']);
ok('core parse', $core['modified'] === ['wp-includes/functions.php'] && $core['extra'] === ['wp-admin/shell.php']
    && $core['missing'] === ['readme.html'] && $core['error'] === null, $core);
$core = ChecksumsCheck::parseCore("Error: Couldn't get checksums from WordPress.org.\n");
ok('core parse error', $core['error'] === "Couldn't get checksums from WordPress.org.", $core);
ok('core parse success', ChecksumsCheck::parseCore("Success: WordPress installation verifies against checksums.\n")['success']);
$colored = new WpSecMon\WpResult(1, '', "\e[36;1mWarning: \e[0m File should not exist: wp-admin/x.php\n");
ok('core parse after ANSI stripping', ChecksumsCheck::parseCore($colored->stderr)['extra'] === ['wp-admin/x.php'], $colored->stderr);
$g = ChecksumsCheck::groupPluginErrors([
    ['plugin_name' => 'akismet', 'file' => 'akismet.php', 'message' => 'Checksum does not match'],
    ['plugin_name' => 'akismet', 'file' => 'x.php', 'message' => 'File was added'],
    ['plugin_name' => 'cache', 'file' => 'cache/a.html', 'message' => 'File was added'],
], ['cache/cache/*']);
ok('plugin errors grouped + ignored', array_keys($g) === ['akismet'] && count($g['akismet']) === 2, $g);

// ---------------------------------------------------------------- file scan
$tmp = sys_get_temp_dir() . '/wpm-scan-' . getmypid();
mkdir("$tmp/site/wp-content/uploads/2026", 0700, true);
mkdir("$tmp/site/wp-content/mu-plugins", 0700, true);
file_put_contents("$tmp/site/wp-config.php", "<?php\n");
file_put_contents("$tmp/site/index.php", "<?php\n");
file_put_contents("$tmp/site/radio.php", "<?php eval(\$_POST[1]);\n");
file_put_contents("$tmp/site/wp-content/mu-plugins/loader.php", "<?php\n");
file_put_contents("$tmp/site/wp-content/uploads/index.php", "<?php\n// Silence is golden.\n");
file_put_contents("$tmp/site/wp-content/uploads/2026/index.php", "<?php // Silence is golden\neval(\$_GET[1]);\n");
file_put_contents("$tmp/site/wp-content/uploads/2026/photo.php.jpg", 'x');
file_put_contents("$tmp/site/wp-content/uploads/2026/photo.jpg", 'x');
// Compiled Twig templates (WPML cache) are harmless; look-alikes are not.
$twig = "$tmp/site/wp-content/uploads/cache/wpml/twig";
mkdir("$twig/00", 0700, true);
mkdir("$twig/ab", 0700, true);
$template = "<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Environment;\nuse \\WPML\\Core\\Twig\\Source;\n"
    . "use \\WPML\\Core\\Twig\\Template;\n\n/* table-slot.twig */\nclass __TwigTemplate_" . hash('sha256', 'a')
    . " extends \\WPML\\Core\\Twig\\Template\n{\n    public function __construct(Environment \$env)\n    {\n";
$h1 = '00' . substr(hash('sha256', '1'), 2);
$h2 = 'ab' . substr(hash('sha256', '2'), 2);
$h3 = '00' . substr(hash('sha256', '3'), 2);
file_put_contents("$twig/00/$h1.php", $template);
file_put_contents("$twig/ab/$h2.php", "<?php\n/* x */ passthru(\$_GET['c']); /* y */\n" . substr($template, 6));
file_put_contents("$twig/ab/$h3.php", $template);
file_put_contents("$twig/00/shell.php", $template);
$scan = WpSecMon\FileScanner::scan(['root' => "$tmp/site", 'content' => "$tmp/site/wp-content",
    'mu' => "$tmp/site/wp-content/mu-plugins", 'uploads' => "$tmp/site/wp-content/uploads"]);
$found = [];
foreach ($scan['entries'] as $e) {
    $found[] = $e['area'] . ':' . substr($e['path'], strlen("$tmp/site/")) . ($e['benign'] ? ':benign' : '');
}
sort($found);
ok('file scan', $found === [
    'mu:wp-content/mu-plugins/loader.php', 'root:index.php', 'root:radio.php', 'root:wp-config.php',
    'uploads:wp-content/uploads/2026/index.php', 'uploads:wp-content/uploads/2026/photo.php.jpg',
    "uploads:wp-content/uploads/cache/wpml/twig/00/$h1.php:benign",
    'uploads:wp-content/uploads/cache/wpml/twig/00/shell.php',
    "uploads:wp-content/uploads/cache/wpml/twig/ab/$h3.php",
    "uploads:wp-content/uploads/cache/wpml/twig/ab/$h2.php",
    'uploads:wp-content/uploads/index.php:benign',
], $found);
Util::rmTree($tmp);

// ---------------------------------------------------------------- run as
ok('refuses root', RunAs::refusal(['name' => 'toor', 'uid' => 0, 'gid' => 0, 'home' => '/'], []) === 'it is root');
ok('refuses primary group root', RunAs::refusal(['name' => 'operator', 'uid' => 11, 'gid' => 0, 'home' => '/'], []) === 'its primary group is root');

$me = Util::passwd(Util::effectiveUid());
$tmp = realpath(sys_get_temp_dir()) . '/wpm-path-' . getmypid();
mkdir("$tmp/www/site", 0700, true);
chmod("$tmp/www", 0755);
ok('site path safe', RunAs::unsafePath("$tmp/www/site", $me) === null, RunAs::unsafePath("$tmp/www/site", $me));
chmod("$tmp/www", 0777);
ok('parent writable by anyone', RunAs::unsafePath("$tmp/www/site", $me) === "$tmp/www is writable by other accounts");
chmod("$tmp/www", 01777);
ok('sticky parent', RunAs::unsafePath("$tmp/www/site", $me) === null);
chmod("$tmp/www", 0755);
chmod("$tmp/www/site", 0777);
ok('site root itself may be writable', RunAs::unsafePath("$tmp/www/site", $me) === null);
symlink("$tmp/www/site", "$tmp/www/link");
ok('symlinked site', RunAs::unsafePath("$tmp/www/link", $me) === "$tmp/www/link is a symbolic link or not a directory");
if ($me['uid'] !== 0) {
    ok('directory of another account', strpos((string) RunAs::unsafePath("$tmp/www/site", ['uid' => $me['uid'] + 1] + $me), ' belongs to ') !== false);
}
Util::rmTree($tmp);

// ---------------------------------------------------------------- output limits
$out = tempnam(sys_get_temp_dir(), 'wpg');
$err = tempnam(sys_get_temp_dir(), 'wpg');
file_put_contents($out, "6.8.1\n");
file_put_contents($err, '');
$r = WpResult::fromFiles(0, $out, $err, 1024);
ok('output read and deleted', $r->ok() && $r->stdout === "6.8.1\n" && !file_exists($out) && !file_exists($err));
file_put_contents($out, str_repeat('x', 2048));
file_put_contents($err, '');
$r = WpResult::fromFiles(0, $out, $err, 1024);
ok('output over max_output_mb', $r->code === RunAs::TOO_MUCH_OUTPUT && $r->stdout === '' && $r->reason() === 'too much output (see max_output_mb)', $r);
file_put_contents($out, '[]');
file_put_contents($err, str_repeat("\n", 200001));
$r = WpResult::fromFiles(0, $out, $err, 1 << 20);
ok('too many lines', $r->code === RunAs::TOO_MUCH_OUTPUT && $r->stdout === '[]' && $r->stderr === '');

// ---------------------------------------------------------------- config
$ini = tempnam(sys_get_temp_dir(), 'wpg');
file_put_contents($ini, "[discovery]\nscan_paths[] = /srv\nscan_paths[] = /var/www\n[alerts]\nalert_on_resolve = no\nalert_repeat_hours = 6\n[users]\nusers_alert_new = privileged\n");
$cfg = Config::load($ini);
ok('config list', $cfg->list('scan_paths') === ['/srv', '/var/www']);
ok('config bool/int', $cfg->bool('alert_on_resolve') === false && $cfg->int('alert_repeat_hours') === 6);
ok('config default kept', $cfg->str('wp_cli') === '/usr/local/bin/wp' && $cfg->str('users_alert_new') === 'privileged');
file_put_contents($ini, "users_alert_new = sometimes\n");
try {
    Config::load($ini);
    ok('config rejects invalid choice', false);
} catch (RuntimeException $e) {
    ok('config rejects invalid choice', true);
}
unlink($ini);

// ---------------------------------------------------------------- alerts
$state = sys_get_temp_dir() . '/wpg-test-' . getmypid();
$cfg = Config::fromArray(['state_dir' => $state, 'log_dir' => $state, 'alert_repeat_hours' => 24]);
$site = new WpSecMon\Site('/home/a/public_html', '/home/a/public_html/wp-config.php', 'a');
$raw = static function (Alerts $a): array {
    $p = new ReflectionProperty(Alerts::class, 'records');
    $p->setAccessible(true);
    return $p->getValue($a);
};
$records = static function (Alerts $a) use ($raw): array {
    return array_map([Report::class, 'fullTitle'], $raw($a));
};
$a = new Alerts($cfg);
$a->setSite($site);
$a->alert('critical', 'core-checksums', 'Core modified', 'x');
$a->alert('critical', 'plugin-checksums.akismet', 'Akismet modified', 'y');
$a->alert('critical', 'plugin-checksums.hello', 'Hello modified', 'z');
ok('alert emitted', $records($a) === ['Core modified', 'Akismet modified', 'Hello modified']);
$a = new Alerts($cfg);
$a->setSite($site);
$a->alert('critical', 'core-checksums', 'Core modified', 'x');
ok('unchanged alert suppressed', $records($a) === [] && $a->suppressed === 1);
$a->alert('critical', 'core-checksums', 'Core modified', 'x and more');
ok('changed alert re-sent', $records($a) === ['Core modified']);
$a->resolveExcept('plugin-checksums.', ['plugin-checksums.hello']);
ok('resolveExcept', $records($a) === ['Core modified', 'Resolved: Akismet modified'], $records($a));
$a->resolve('core-checksums');
$a->resolve('core-checksums');
ok('resolve once', count(Alerts::openAlerts($state)) === 1);
Util::rmTree($state);

// ---------------------------------------------------------------- report
$state = sys_get_temp_dir() . '/wpg-report-' . getmypid();
$cfg = Config::fromArray(['state_dir' => $state, 'log_dir' => $state]);
Util::writeJson("$state/sites/{$site->id}/options.json", ['home' => 'https://shop.example/']);
$v = static function (?string $severity, ?string $fixed, bool $unfixed = false): array {
    return ['title' => 'x', 'cves' => [], 'link' => '', 'severity' => $severity, 'score' => null, 'unfixed' => $unfixed, 'fixed' => $fixed];
};
[$sev, $title, $lines, $meta] = VulnsCheck::describe('Plugin Evil 1.0', [$v('medium', '2.5'), $v('high', '2.0'), $v('low', null, true)]);
ok('describe meta', $meta === ['count' => 3, 'fix' => '2.5', 'unfixed' => 1, 'risk' => 'high'], $meta);
$a = new Alerts($cfg);
$a->setSite($site);
$a->event('warning', '1 new account(s) created', '    #5 bob', ['kind' => 'users-new']);
$a->alert($sev, 'vuln.plugin.evil', $title, $lines, null, null,
    ['type' => 'plugin', 'slug' => 'evil', 'name' => '<img src=x onerror=alert(1)>', 'version' => '1.0', 'active' => true] + $meta);
$a->alert('critical', 'uploads-exec', '2 executable file(s) in the uploads directory', '    wp-content/uploads/shell.php (10 bytes)',
    null, null, ['count' => 2]);
$a->event('critical', 'New privileged account: eve (administrator)', '    #6 eve', ['kind' => 'admin-new']);
$a->setSite(null);
$a->alert('warning', 'vulndb-unreachable', 'Vulnerability database unreachable', '');
$report = new Report($raw($a), ['host' => 'web1', 'checks' => 'all', 'started' => time(), 'duration' => 1, 'sites' => 1, 'errors' => 0,
    'count' => ['critical' => 3, 'warning' => 2, 'info' => 0], 'details' => '/var/log/wp-secmon/last-report-all.txt', 'log' => '/var/log/wp-secmon/alerts.log'], $cfg);
[$sites, $server] = $report->model();
$todo = array_map(static function ($t) {
    return substr($t[1], 0, 25);
}, $sites[0]['todo'] ?? []);
ok('advice: compromise first, then updates, then changes to confirm', $todo === [
    'Confirm that each new adm', 'The uploads folder, which', 'Update 1 plugin with know', 'New accounts were created',
], $todo);
ok('update row', ($sites[0]['updates'][0]['fix'] ?? null) === '2.5' && $sites[0]['updates'][0]['unfixed'] === 1, $sites[0]['updates']);
ok('site address from the last integrity check', $sites[0]['url'] === 'shop.example', $sites[0]['url']);
ok('monitoring problems go to the server notes', count($sites) === 1 && array_column($server, 'kind') === ['vulndb-unreachable']);
$html = $report->html();
ok('html escapes site data', strpos($html, '<img') === false && strpos($html, '&lt;img src=x onerror=alert(1)&gt;') !== false);
ok('html leaves details out', strpos($html, 'shell.php') === false && strpos($html, 'What to do') !== false);
$text = $report->text(false);
ok('text summary', strpos($text, 'Updates needed') !== false && strpos($text, 'shell.php') === false && strpos($text, "\e") === false, $text);
ok('text colors on request', strpos($report->text(true), "\e[1;31m") !== false);
ok('details keep everything', strpos($report->details(), 'wp-content/uploads/shell.php (10 bytes)') !== false);

[$headers, $body] = Alerts::mime("plain text\n", '<p>html</p>', 'b0');
$parts = explode("--b0", $body);
ok('mime headers', $headers === ['Content-Type: multipart/alternative; boundary="b0"', 'Content-Transfer-Encoding: 8bit'], $headers);
ok('mime parts', count($parts) === 4 && trim($parts[3]) === '--' && strpos($parts[1], "text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\nplain text\n") !== false
    && base64_decode(trim(explode("\n\n", $parts[2], 2)[1])) === '<p>html</p>', $body);

// Forgetting open alerts keeps the baselines.
$other = new WpSecMon\Site('/home/b/public_html', '/home/b/public_html/wp-config.php', 'b');
Util::writeJson("$state/sites/{$other->id}/alerts/core-checksums.json", ['title' => 'x', 'severity' => 'critical']);
Util::writeFile("$state/sites/{$site->id}/users.json", "[]\n");
ok('forget one site', Alerts::forget($state, [$site->id]) === 2 && count(Alerts::openAlerts($state)) === 2);
ok('forget everything', Alerts::forget($state) === 2 && Alerts::openAlerts($state) === [] && is_file("$state/sites/{$site->id}/users.json"));
Util::rmTree($state);

// ---------------------------------------------------------------- rediscovering one site
$tmp = sys_get_temp_dir() . '/wpm-sites-' . getmypid();
foreach (['one', 'two'] as $name) {
    mkdir("$tmp/www/$name/wp-includes", 0700, true);
    foreach (['wp-load.php', 'wp-settings.php', 'wp-config.php', 'wp-includes/version.php'] as $file) {
        file_put_contents("$tmp/www/$name/$file", "<?php\n");
    }
}
$cfg = Config::fromArray(['state_dir' => "$tmp/state", 'log_dir' => "$tmp/state", 'scan_paths' => ["$tmp/www"]]);
$sites = new Sites($cfg, new Alerts($cfg));
$all = static function (array $reg): array {
    return array_merge(array_column($reg['sites'], 'root'), array_column($reg['skipped'], 'root'));
};
$full = $sites->discover();
$all1 = $all($full);
sort($all1);
ok('discovery finds both sites', $all1 === ["$tmp/www/one", "$tmp/www/two"], $full);
unlink("$tmp/www/two/wp-config.php");
unlink("$tmp/www/one/wp-config.php");
// Only "two" is examined again, given as discovery found it or with its symbolic links resolved.
$reg = $sites->discover(["$tmp/www/two/", "$tmp/www/elsewhere"]);
ok('rediscovery updates only the given site', $reg['orphans'] === ["$tmp/www/two"] && $all($reg) === ["$tmp/www/one"], $reg);
$reg = $sites->discover([Sites::root("$tmp/www/one")]);
sort($reg['orphans']);
ok('rediscovery with the real path', $reg['orphans'] === ["$tmp/www/one", "$tmp/www/two"] && $all($reg) === [], $reg);
ok('rediscovery keeps the date of the last full discovery', $reg['generated'] === $full['generated']);
Util::rmTree($tmp);

// ---------------------------------------------------------------- downloads and updates
$sum = hash('sha256', 'phar');
ok('checksum as written by sha256sum', Http::checksumMatches('phar', "$sum  wp-secmon.phar\n", 'sha256'));
ok('checksum alone, upper case', Http::checksumMatches('phar', strtoupper($sum), 'sha256'));
ok('checksum mismatch', !Http::checksumMatches('phar!', $sum, 'sha256') && !Http::checksumMatches('phar', '', 'sha256')
    && !Http::checksumMatches('phar', "\n", 'sha256'));
$asset = static function (string $name): array {
    return ['name' => $name, 'browser_download_url' => "https://github.com/webo3/wp-secmon/releases/download/v1.2.3/$name"];
};
$release = ['tag_name' => 'v1.2.3', 'assets' => [$asset('wp-secmon.phar.sha256'), $asset('wp-secmon.phar'), $asset('other.zip')]];
ok('release parsed', Updater::parseRelease((string) json_encode($release)) === ['version' => '1.2.3',
    'phar' => 'https://github.com/webo3/wp-secmon/releases/download/v1.2.3/wp-secmon.phar',
    'sha256' => 'https://github.com/webo3/wp-secmon/releases/download/v1.2.3/wp-secmon.phar.sha256']);
ok('release without its checksum refused', Updater::parseRelease((string) json_encode(['assets' => [$asset('wp-secmon.phar')]] + $release)) === null);
ok('release with an odd tag refused', Updater::parseRelease((string) json_encode(['tag_name' => 'v1.2.3/../x'] + $release)) === null
    && Updater::parseRelease((string) json_encode(['tag_name' => 'v1.2.3-rc1'] + $release)) === null);
ok('release from a non-HTTP URL refused', Updater::parseRelease((string) json_encode(['assets' => [$asset('wp-secmon.phar.sha256'),
    ['name' => 'wp-secmon.phar', 'browser_download_url' => 'file:///etc/passwd']]] + $release)) === null);
ok('not a release', Updater::parseRelease('{"message":"Not Found"}') === null && Updater::parseRelease('<html>') === null);

// ---------------------------------------------------------------- translations
[$messages, $problems] = i18nMessages(dirname(__DIR__) . '/src');
ok('translated messages are literals', $problems === [], $problems);
ok('messages found in the code', count($messages) > 300, count($messages));
$fr = require dirname(__DIR__) . '/resources/lang/fr.php';
$months = [];
for ($m = 1; $m <= 12; $m++) {
    $months[date('F', mktime(12, 0, 0, $m, 1, 2000))] = $months[date('M', mktime(12, 0, 0, $m, 1, 2000))] = true;
}
ok('every message has a French translation', array_keys(array_diff_key($messages, $fr)) === [], array_keys(array_diff_key($messages, $fr)));
ok('no stale French translation', array_keys(array_diff_key($fr, $messages, $months)) === [], array_keys(array_diff_key($fr, $messages, $months)));
$bad = [];
foreach (array_intersect_key($fr, $messages) as $key => $tr) {
    $forms = $messages[$key] === null ? [$key] : [$key, $messages[$key]];
    if (count((array) $tr) !== count($forms)) {
        $bad[] = "$key: " . ($messages[$key] === null ? 'not a plural message' : 'needs [singular, plural]');
        continue;
    }
    foreach (array_values((array) $tr) as $i => $text) {
        if (strpos($forms[$i], '%') !== false && conversions($forms[$i]) !== conversions($text)) {
            $bad[] = "$key: placeholders differ";
        }
    }
}
ok('French translations keep the placeholders', $bad === [], $bad);

ok('English plural: 0 is plural', I18n::n(0, '%d site', '%d sites', 0) === '0 sites' && I18n::n(1, '%d site', '%d sites', 1) === '1 site');
ok('context falls back to the English message', I18n::tc('theme', 'inactive') === 'inactive');
I18n::setLanguage('fr');
ok('French plural: 0 and 1 are singular', I18n::n(0, '%d site checked', '%d sites checked', 0) === '0 site vérifié'
    && I18n::n(2, '%d site checked', '%d sites checked', 2) === '2 sites vérifiés');
ok('French translation with context', I18n::tc('theme', 'inactive') === 'inactif' && I18n::tc('plugin', 'inactive') === 'inactive');
ok('French dates', I18n::date('F j, Y, H:i T', mktime(14, 5, 0, 9, 30, 2026)) === date('30 \s\e\p\t\e\m\b\r\e 2026, 14:05 T', mktime(14, 5, 0, 9, 30, 2026))
    && I18n::date('M j', mktime(12, 0, 0, 2, 3, 2026)) === '3 févr.', I18n::date('M j', mktime(12, 0, 0, 2, 3, 2026)));
ok('unknown message falls back to English', I18n::t('not translated %s', 'x') === 'not translated x');
ok('accented upper case', Util::upper('attention recommandée') === 'ATTENTION RECOMMANDÉE' && Util::width('é·') === 2);
$state = sys_get_temp_dir() . '/wpg-report-fr-' . getmypid();
$cfg = Config::fromArray(['state_dir' => $state, 'log_dir' => $state]);
$a = new Alerts($cfg);
$a->check = 'users';
$a->setSite($site);
foreach (UsersCheck::diff($old, $new, ['administrator'], 'all', 'warning') as [$sev, $title, $lines, $kind]) {
    $a->event($sev, $title, $lines, ['kind' => $kind]);
}
$report = new Report($raw($a), ['host' => 'web1', 'checks' => 'users', 'started' => time(), 'duration' => 1, 'sites' => 1, 'errors' => 0,
    'count' => ['critical' => 2, 'warning' => 3, 'info' => 1], 'details' => '/var/log/wp-secmon/last-report-users.txt', 'log' => '/var/log/wp-secmon/alerts.log'], $cfg);
$text = $report->text(false);
ok('French report', strpos($text, 'Que faire') !== false && strpos($text, 'Nouveau compte privilégié : wp [31mhack (administrator)') !== false
    && strpos($text, 'AVERTISSEMENT  ') !== false && strpos($report->html(), '<html lang="fr">') !== false, $text);
ok('French details', strpos($report->details(), '[CRITIQUE] users: Privilèges accordés au compte : bob') !== false, $report->details());
Util::rmTree($state);
I18n::setLanguage('en');
try {
    Config::fromArray(['language' => 'de']);
    ok('config rejects an unknown language', false);
} catch (RuntimeException $e) {
    ok('config rejects an unknown language', true);
}

fwrite(STDOUT, sprintf("%d/%d tests passed\n", $count - $failures, $count));
exit($failures ? 1 : 0);
