<?php
/**
 * wp-secmon end-to-end test, run as root inside tests/integration/Dockerfile.
 *
 * Builds real WordPress sites owned by separate accounts, simulates common
 * attacks and checks that wp-secmon reports them, runs nothing as root and
 * changes nothing (database checksums and file metadata are compared).
 */

declare(strict_types=1);

const MAIL = '/tmp/mail.txt';
const ALICE = '/home/alice/public_html';
const BOB = '/home/bob/public_html/blog';
const ROOTSITE = '/var/www/rootsite';
// The version being tested, as set in src/bootstrap.php.
define('VERSION', preg_match("/const VERSION = '([^']+)'/", (string) file_get_contents('/src/src/bootstrap.php'), $m) ? $m[1] : '?');

$passed = 0;
$failed = 0;

function sh(array $cmd, bool $must = true, string $input = ''): array
{
    $in = tempnam('/tmp', 'i');
    $out = tempnam('/tmp', 'o');
    $err = tempnam('/tmp', 'e');
    file_put_contents($in, $input);
    $p = proc_open($cmd, [0 => ['file', $in, 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
    $code = proc_close($p);
    $r = [$code, (string) file_get_contents($out), (string) file_get_contents($err)];
    unlink($in);
    unlink($out);
    unlink($err);
    if ($must && $code !== 0) {
        fwrite(STDERR, "command failed ($code): " . implode(' ', $cmd) . "\n{$r[1]}{$r[2]}\n");
        exit(2);
    }
    return $r;
}

function wp(string $user, string $path, array $args): array
{
    $cmd = $user === 'root'
        ? array_merge(['wp', '--allow-root', "--path=$path"], $args)
        : array_merge(['runuser', '-u', $user, '--', 'wp', "--path=$path"], $args);
    return sh($cmd);
}

function sql(string $q): string
{
    return sh(['mysql', '-uroot', '-N', '-e', $q])[1];
}

function put(string $file, string $content, string $owner, bool $append = false): void
{
    file_put_contents($file, $content, $append ? FILE_APPEND : 0);
    chown($file, $owner);
    chgrp($file, $owner);
}

/** Just enough of a WordPress install for discovery to find it. */
function fakeSite(string $path, string $owner): void
{
    sh(['mkdir', '-p', "$path/wp-includes"]);
    foreach (['wp-load.php', 'wp-settings.php', 'wp-config.php', 'wp-includes/version.php'] as $file) {
        file_put_contents("$path/$file", "<?php\n");
    }
    sh(['chown', '-R', "$owner:$owner", $path]);
}

/** Session id of the current process, without the posix extension. */
function sessionId(): string
{
    return explode(' ', (string) file_get_contents('/proc/self/stat'))[5] ?? '';
}

/** Run wp-secmon; returns [exit code, stdout+stderr, mailed report, detailed report (last-report-*.txt)]. */
function wpsecmon(string ...$args): array
{
    return wpsecmonWithInput('', ...$args);
}

/** wpsecmon() with $input on stdin (answers to review). */
function wpsecmonWithInput(string $input, string ...$args): array
{
    @unlink(MAIL);
    foreach (glob('/var/log/wp-secmon/last-report-*.txt') ?: [] as $file) {
        unlink($file);
    }
    [$code, $out, $err] = sh(array_merge(['wp-secmon'], $args), false, $input);
    $mail = (string) @file_get_contents(MAIL);
    $details = '';
    foreach (glob('/var/log/wp-secmon/last-report-*.txt') ?: [] as $file) {
        $details .= file_get_contents($file);
    }
    echo "\$ wp-secmon " . implode(' ', $args) . " (exit $code)\n";
    return [$code, $out . $err, $mail, $details];
}

/** The HTML part of a mailed report, decoded. */
function mailHtml(string $mail): string
{
    if (!preg_match('#Content-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n([A-Za-z0-9+/=\n]+)#', $mail, $m)) {
        return '';
    }
    return (string) base64_decode(str_replace("\n", '', $m[1]));
}

function expect(string $name, bool $cond, string $context = ''): void
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
        echo "  ok   $name\n";
        return;
    }
    $failed++;
    echo "  FAIL $name\n";
    if ($context !== '') {
        echo '       ' . str_replace("\n", "\n       ", trim($context)) . "\n";
    }
}

function has(string $haystack, string $needle): bool
{
    return strpos($haystack, $needle) !== false;
}

/** Everything wp-secmon must never change: table checksums and file metadata. */
function snapshot(): array
{
    $tables = array_filter(explode("\n", sql("SELECT CONCAT(table_schema, '.', table_name) FROM information_schema.tables WHERE table_schema LIKE 'wp\\_%'")));
    $db = sql('CHECKSUM TABLE ' . implode(', ', $tables) . ' EXTENDED');
    // Except the logs each account gets in ~/logs and the state of its own runs in ~/.wp-secmon
    // (which change the size and time of its home).
    [, $files] = sh(['find', '/home', '/var/www', '-regex', '/home/[^/]*/\(logs\|\.wp-secmon\)', '-prune', '-o', '-printf', '%p %s %T@ %m %U:%G\n']);
    $files = explode("\n", (string) preg_replace('#^(/home/[^/ ]+) \d+ [\d.]+ #m', '$1 - - ', $files));
    sort($files);
    return ['db' => $db, 'files' => $files];
}

function sameSnapshot(array $a, array $b): string
{
    $diff = array_merge(array_diff($b['files'], $a['files']), array_diff($a['files'], $b['files']));
    $out = $a['db'] === $b['db'] ? '' : "database changed\n";
    return $out . ($diff ? "files changed:\n" . implode("\n", array_slice($diff, 0, 20)) : '');
}

function step(string $title): void
{
    echo "\n=== $title\n";
}

// ---------------------------------------------------------------------------
step('setup');
echo 'PHP ' . PHP_VERSION . ', posix extension: ' . (function_exists('posix_getpwnam') ? 'yes' : 'no') . "\n";
if (is_executable('/usr/sbin/service')) {
    sh(['service', 'mariadb', 'start']);
} else {
    // EL images have no init system.
    sh(['mysql_install_db', '--user=mysql']);
    exec('mysqld_safe --user=mysql > /dev/null 2>&1 &');
    for ($i = 0; $i < 60 && sh(['mysqladmin', 'ping'], false)[0] !== 0; $i++) {
        sleep(1);
    }
}
sh(['useradd', '-m', '-u', '1001', '-s', '/bin/bash', 'alice']);
sh(['useradd', '-m', '-u', '1002', '-s', '/bin/bash', 'bob']);
if (sh(['id', 'www-data'], false)[0] !== 0) {
    sh(['useradd', '-r', '-s', '/sbin/nologin', 'www-data']);
}
foreach (['alice', 'bob', 'wproot'] as $u) {
    $db = $u === 'wproot' ? 'wp_root' : "wp_$u";
    sql("CREATE DATABASE $db; CREATE USER '$u'@'localhost' IDENTIFIED BY 'pw-$u'; GRANT ALL ON $db.* TO '$u'@'localhost';");
}

$sites = [
    [ALICE, 'alice', 'wp_alice', 'http://alice.test'],
    [BOB, 'bob', 'wp_bob', 'http://bob.test/blog'],
    [ROOTSITE, 'root', 'wp_root', 'http://root.test'],
];
foreach ($sites as [$path, $user, $db, $url]) {
    sh(['mkdir', '-p', $path]);
    sh(['cp', '-a', '/opt/wp-core/.', $path]);
    if ($user !== 'root') {
        sh(['chown', '-R', "$user:$user", dirname($path)]);
    }
    $dbUser = $user === 'root' ? 'wproot' : $user;
    wp($user, $path, ['config', 'create', "--dbname=$db", "--dbuser=$dbUser", "--dbpass=pw-$dbUser", '--dbhost=localhost', '--skip-check']);
    wp($user, $path, ['core', 'install', "--url=$url", '--title=Test', '--admin_user=admin', '--admin_password=pw',
        '--admin_email=admin@example.test', '--skip-email']);
}
// Bob keeps wp-config.php one level above WordPress (supported by WordPress).
rename(BOB . '/wp-config.php', dirname(BOB) . '/wp-config.php');
// Alice runs a vulnerable Contact Form 7 and has harmless PHP in uploads: a "Silence is golden" stub,
// a compiled Twig template (WPML cache), Sucuri data files and dompdf font metrics.
wp('alice', ALICE, ['plugin', 'install', 'contact-form-7', '--version=5.3.1', '--activate', '--quiet']);
sh(['runuser', '-u', 'alice', '--', 'mkdir', '-p', ALICE . '/wp-content/uploads/2026/09', ALICE . '/wp-content/uploads/cache/wpml/twig/3f',
    ALICE . '/wp-content/uploads/sucuri', ALICE . '/wp-content/uploads/wpo_wcpdf_0123/fonts']);
put(ALICE . '/wp-content/uploads/2026/index.php', "<?php\n// Silence is golden.\n", 'alice');
put(ALICE . '/wp-content/uploads/cache/wpml/twig/3f/3f' . substr(hash('sha256', 'tpl'), 2) . '.php',
    "<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Template;\n\n/* slot.twig */\n"
    . 'class __TwigTemplate_' . hash('sha256', 'slot') . " extends \\WPML\\Core\\Twig\\Template\n{\n}\n", 'alice');
put(ALICE . '/wp-content/uploads/sucuri/sucuri-lastlogins.php', "<?php exit(0); ?>\n", 'alice');
put(ALICE . '/wp-content/uploads/sucuri/sucuri-integrity.php', "<?php\n// datastore=integrity;\n// created_on=1790000000;\nexit(0);\n?>\n"
    . "wp-config.php:{\"checksum\":\"abc\"}\n", 'alice');
put(ALICE . '/wp-content/uploads/wpo_wcpdf_0123/fonts/OpenSans-Normal.ufm.php', '<?php return '
    . var_export(['FontName' => 'OpenSans', 'isUnicode' => true, 'C' => [32 => 260, 33 => 267], 'Descender' => -240.0], true) . ';', 'alice');
put('/usr/local/bin/fake-sendmail', "#!/usr/bin/php\n<?php file_put_contents('" . MAIL . "', stream_get_contents(STDIN), FILE_APPEND);\n", 'root');
chmod('/usr/local/bin/fake-sendmail', 0755);

// Build the phar and install it the way a server would, on a server without WP-CLI.
[, $out] = sh(['php', '-d', 'phar.readonly=0', '/src/build.php']);
echo $out;
copy('/src/dist/wp-secmon.phar', '/root/wp-secmon.phar');
rename('/usr/local/bin/wp', '/root/wp-cli.phar');
[$code, $out] = sh(['php', '/root/wp-secmon.phar', 'install']);
echo $out;
$st = @stat('/usr/local/bin/wp');
expect('install downloads WP-CLI', has($out, 'WP-CLI: /usr/local/bin/wp (downloaded)') && $st && $st['uid'] === 0 && ($st['mode'] & 0777) === 0755, $out);
file_put_contents('/etc/wp-secmon/wp-secmon.ini', "[discovery]\nscan_paths[] = /home\nscan_paths[] = /var/www\n[alerts]\nsendmail = /usr/local/bin/fake-sendmail\n");
$bin = '/usr/local/bin/wp-secmon';
$st = stat($bin);
expect('installed the phar as ' . $bin, is_file($bin) && hash_file('sha256', $bin) === hash_file('sha256', '/root/wp-secmon.phar'));
expect('installed program is root-owned and not writable by others', $st['uid'] === 0 && ($st['mode'] & 0777) === 0755);
expect('installed program runs', trim(sh([$bin, '--version'])[1]) === 'wp-secmon ' . VERSION);
[$code, $out] = sh(['php', '/root/wp-secmon.phar', 'install']);
expect('reinstall keeps the configuration', has($out, 'kept /etc/wp-secmon/wp-secmon.ini') && has((string) file_get_contents('/etc/wp-secmon/wp-secmon.ini'), 'fake-sendmail'), $out);
expect('reinstall keeps WP-CLI', has($out, 'WP-CLI: /usr/local/bin/wp') && !has($out, '(downloaded)') && !has($out, 'Next steps'), $out);

// ---------------------------------------------------------------------------
step('doctor');
[$code, $out] = wpsecmon('doctor');
echo $out;
expect('doctor passes', $code === 0, $out);
expect('doctor uses setpriv', has($out, 'user switching: setpriv'));
expect('doctor shows where the accounts get their logs', has($out, 'each account gets the logs of its own sites in ~/logs/wp-secmon'), $out);

step('discovery');
[, $out, $mail, $details] = wpsecmon('sites');
echo $out;
expect('sites runs the first discovery', has($out, 'no site list yet: discovering the WordPress installs first') && is_file('/var/lib/wp-secmon/sites.json'), $out);
expect('unmonitored root-owned site reported', $mail !== '' && has($details, 'Site is not monitored: owned by root'), $details);
expect('finds alice as alice', (bool) preg_match('#^alice\s+-\s+-\s+' . ALICE . '$#m', $out), $out);
expect('finds bob (wp-config.php in parent) as bob', (bool) preg_match('#^bob\s+-\s+-\s+' . BOB . '$#m', $out), $out);
expect('root-owned site is not checked as root', has($out, "Not monitored:\n  " . ROOTSITE) && has($out, 'owned by root'), $out);

// ---------------------------------------------------------------------------
step('first run: baselines');
[$code, $out, $mail, $details] = wpsecmon('all', '--print');
echo $out;
$html = mailHtml($mail);
expect('report e-mailed', has($mail, 'Subject: [wp-secmon]'), $out);
expect('e-mail is HTML with a text alternative', has($mail, 'Content-Type: multipart/alternative') && has($mail, "Content-Type: text/plain")
    && has($html, '<!DOCTYPE html>'), $mail);
expect('vulnerable Contact Form 7 reported', has($details, 'Plugin Contact Form 7 5.3.1 (contact-form-7, active)') && has($details, 'CVE-2020-35489'), $details);
expect('e-mail says what to update', has($html, 'Updates needed') && has($html, 'Contact Form 7') && (bool) preg_match('/Update \d+ plugins?( and \d+ themes?)? with known security holes/', $html), $html);
expect('e-mail leaves the CVE list to the details', !has($html, 'CVE-2020-35489') && !has($mail, 'CVE-2020-35489'), $html);
expect('printed summary', has($out, 'What to do') && has($out, 'Details: /var/log/wp-secmon/last-report-'), $out);
expect('no check failed', !has($out . $details, 'Check failed'), $out . $details);
expect('clean installs match the official checksums', !has($details, 'checksums:'), $details);
expect('no account alerts on the baseline run', !has($details, 'account'), $details);
expect('harmless PHP in uploads not reported (stub, Twig cache, Sucuri data, dompdf fonts)', !has($details, 'executable file'), $details);

step('logs of each account');
const ALICE_LOGS = '/home/alice/logs/wp-secmon';
$aliceLog = (string) @file_get_contents(ALICE_LOGS . '/alerts.log');
$aliceReport = implode('', array_map('file_get_contents', glob(ALICE_LOGS . '/last-report-*.txt') ?: []));
$bobLogs = implode('', array_map('file_get_contents', glob('/home/bob/logs/wp-secmon/*') ?: []));
$dirSt = @stat(ALICE_LOGS);
$logSt = @stat(ALICE_LOGS . '/alerts.log');
expect('alice gets the alerts and details of her site', has($aliceLog, 'site=' . ALICE . ' user=alice') && has($aliceReport, 'CVE-2020-35489'), $aliceLog . $aliceReport);
expect('written as alice, for alice only', $dirSt && $dirSt['uid'] === 1001 && ($dirSt['mode'] & 0777) === 0700
    && $logSt && $logSt['uid'] === 1001 && ($logSt['mode'] & 0777) === 0600);
expect('nothing about the other sites or the server', !has($aliceLog . $aliceReport, BOB) && !has($aliceLog . $aliceReport, ROOTSITE)
    && !has($aliceLog . $aliceReport, 'not monitored'), $aliceLog . $aliceReport);
expect('bob gets nothing about alice', !has($bobLogs, ALICE), $bobLogs);
expect('the outbox is emptied once delivered', !glob('/var/lib/wp-secmon/outbox/*/last-report-*.txt')
    && implode('', array_map('file_get_contents', glob('/var/lib/wp-secmon/outbox/*/pending.log') ?: [])) === '');

step('second run changes nothing and repeats nothing');
$before = snapshot();
[$code, $out, $mail] = wpsecmon('all');
$after = snapshot();
expect('database and files untouched', ($d = sameSnapshot($before, $after)) === '', $d);
expect('no report when nothing changed', $mail === '', $mail);
expect('unchanged alerts not repeated', (bool) preg_match('/\(([1-9]\d*) unchanged not repeated\)/', $out), $out);

step('reset reports everything again');
$before = snapshot();
[$code, $out] = wpsecmon('reset');
expect('reset forgets the open alerts', $code === 0 && (bool) preg_match('/Forgot [1-9]\d* open alert\(s\)/', $out), $out);
expect('reset keeps the baselines', count(glob('/var/lib/wp-secmon/sites/*/users.json') ?: []) >= 2 && !is_dir('/var/lib/wp-secmon/cache/vulndb'));
[$code, $out, $mail, $details] = wpsecmon('all');
$after = snapshot();
expect('open problems e-mailed again after reset', has($details, 'Plugin Contact Form 7 5.3.1') && !has($details, 'Still present') && $mail !== '', $out);
expect('baselines kept: no user or file changes reported after reset', !has($details, '] users:') && !has($details, '] integrity:'), $details);
expect('database and files untouched by reset', ($d = sameSnapshot($before, $after)) === '', $d);

// ---------------------------------------------------------------------------
step('attack alice');
wp('alice', ALICE, ['user', 'create', 'hacker', 'hacker@evil.test', '--role=administrator', '--quiet']);
wp('alice', ALICE, ['user', 'update', 'admin', '--user_email=attacker@evil.test', '--quiet']);
wp('alice', ALICE, ['option', 'update', 'users_can_register', '1', '--quiet']);
wp('alice', ALICE, ['option', 'update', 'default_role', 'administrator', '--quiet']);
wp('alice', ALICE, ['plugin', 'activate', 'hello', '--quiet']);
// An account inserted straight into the database, with a terminal escape sequence in its login.
sql("USE wp_alice; INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, display_name)
     VALUES (CONCAT('ev', CHAR(27), '[31mil'), 'x', 'evil', 'evil@evil.test', NOW(), 'evil');
     INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}');");
put(ALICE . '/wp-includes/functions.php', "\n// injected\n", 'alice', true);
put(ALICE . '/wp-admin/shell.php', "<?php system(\$_GET['c']);\n", 'alice');
// Not an attack: removed to hide the WordPress version, which must not be reported.
unlink(ALICE . '/readme.html');
put(ALICE . '/radio.php', "<?php eval(\$_POST['x']);\n", 'alice');
put(ALICE . '/wp-config.php', "\n// tampered\n", 'alice', true);
// A web shell dressed as a Sucuri data file: its exit comes too late.
put(ALICE . '/wp-content/uploads/sucuri/sucuri-cmd.php', "<?php passthru(\$_GET['c']); exit(0); ?>\n", 'alice');
put(ALICE . '/wp-content/uploads/2026/09/photo.php.jpg', "<?php phpinfo();\n", 'alice');
put(ALICE . '/wp-content/plugins/contact-form-7/wp-contact-form-7.php', "\n// backdoor\n", 'alice', true);
// Last: a must-use plugin that hides the attacker account and leaves a trace whenever it runs.
sh(['runuser', '-u', 'alice', '--', 'mkdir', '-p', ALICE . '/wp-content/mu-plugins']);
put(ALICE . '/wp-content/mu-plugins/loader.php', "<?php\n@touch('/tmp/mu-plugin-ran');\n"
    . "add_action('pre_user_query', function (\$q) { \$q->query_where .= \" AND user_login <> 'hacker'\"; });\n", 'alice');

$before = snapshot();
[, $outUsers, $usersMail, $users] = wpsecmon('users');
[, $outInteg, $integrityMail, $integrity] = wpsecmon('integrity');
[, $outSums, , $checksums] = wpsecmon('checksums');
[, $outVulns] = wpsecmon('vulns');
$after = snapshot();
echo $users, $integrity, $checksums;

step('read-only and privilege guarantees');
expect('database and files untouched by the checks', ($d = sameSnapshot($before, $after)) === '', $d);
expect('the malicious mu-plugin was never executed', !file_exists('/tmp/mu-plugin-ran'));
expect('no check failed', !has($outUsers . $outInteg . $outSums . $outVulns . $users . $integrity . $checksums, 'Check failed'),
    $outUsers . $outInteg . $outSums . $outVulns);

step('users');
expect('new admin created with WP-CLI', has($users, '[CRITICAL] users: New privileged account: hacker (administrator)'), $users);
expect('admin inserted in the database, escape sequence neutralized',
    has($users, 'New privileged account: ev [31mil (administrator)') && !has($users, "\x1b"), $users);
expect('admin e-mail change', has($users, '[WARNING] users: Privileged account e-mail changed: admin'), $users);
expect('bob untouched', !has($users, BOB), $users);
$html = mailHtml($usersMail);
expect('e-mail: new administrators to confirm', has($html, 'Confirm that each new administrator') && has($html, 'New privileged account: hacker (administrator)'), $html);

step('integrity');
foreach ([
    '[CRITICAL] integrity: Anyone can register and new accounts get the \'administrator\' role',
    '[WARNING] integrity: "Anyone can register" setting changed',
    '[WARNING] integrity: Default role for new accounts changed',
    '[WARNING] integrity: 1 plugin(s) activated',
    '[WARNING] integrity: wp-config.php: 1 modified',
    '[CRITICAL] integrity: Non-core PHP files in the site root: 1 added',
    '[CRITICAL] integrity: Must-use plugins (loaded on every request, cannot be disabled): 1 added',
    '[CRITICAL] integrity: 2 executable file(s) in the uploads directory',
    'wp-content/uploads/2026/09/photo.php.jpg',
    'wp-content/uploads/sucuri/sucuri-cmd.php',
] as $needle) {
    expect($needle, has($integrity, $needle), $integrity);
}
$html = mailHtml($integrityMail);
expect('e-mail: advice without the file list', has($html, 'The uploads folder, which should only hold images and documents, contains 2 PHP or script files')
    && has($html, 'Turn off &quot;Anyone can register&quot;') && !has($html, 'photo.php.jpg') && !has($integrityMail, 'photo.php.jpg'), $html);

step('checksums');
expect('core modification and extra file', has($checksums, '[CRITICAL] checksums: WordPress core files do not match the official checksums: 1 modified, 1 unexpected, 0 missing'), $checksums);
expect('lists the files', has($checksums, 'modified: wp-includes/functions.php') && has($checksums, 'should not exist: wp-admin/shell.php'), $checksums);
expect('plugin modification', has($checksums, "Plugin 'contact-form-7' does not match the wordpress.org checksums"), $checksums);

step('repeat and resolve');
[, , $mail] = wpsecmon('checksums');
expect('unchanged problems are not repeated', $mail === '', $mail);
sh(['cp', '/opt/wp-core/wp-includes/functions.php', ALICE . '/wp-includes/functions.php']);
unlink(ALICE . '/wp-admin/shell.php');
// Under systemd the homes are read-only during the check: the unit delivers the logs afterwards.
clearstatcache();
$logSize = filesize(ALICE_LOGS . '/alerts.log');
putenv('WP_SECMON_DEFER_DELIVERY=1');
[, $out, , $details] = wpsecmon('checksums', '--print', '--no-mail');
putenv('WP_SECMON_DEFER_DELIVERY');
expect('fixed core reported as resolved, with readme.html still missing', has($details, 'Resolved: WordPress core files do not match')
    && has($out, 'Fixed since the last report') && has($out, '✓ WordPress core files do not match') && !has($out . $details, 'Check failed'), $out);
clearstatcache();
expect('logs kept for later when delivery is deferred', filesize(ALICE_LOGS . '/alerts.log') === $logSize
    && has((string) @file_get_contents('/var/lib/wp-secmon/outbox/alice/pending.log'), 'Resolved: WordPress core files do not match'));
[$code] = sh(['wp-secmon', '__deliver']);
expect('logs delivered after the check', $code === 0 && has((string) file_get_contents(ALICE_LOGS . '/alerts.log'), 'Resolved: WordPress core files do not match')
    && file_get_contents('/var/lib/wp-secmon/outbox/alice/pending.log') === '');
[, $out] = wpsecmon('status');
echo $out;
expect('status lists open alerts', has($out, 'executable file(s) in the uploads directory') && !has($out, 'WordPress core files'), $out);

// ---------------------------------------------------------------------------
step('reports to site administrators');
// Alice and bob have the same administration address: one e-mail for both sites, with a copy.
$ini = (string) file_get_contents('/etc/wp-secmon/wp-secmon.ini');
file_put_contents('/etc/wp-secmon/wp-secmon.ini', $ini . "alert_site_admins = yes\nalert_site_admins_cc[] = soc@example.test\n");
wp('alice', ALICE, ['plugin', 'deactivate', 'hello', '--quiet']);
wp('bob', BOB, ['plugin', 'activate', 'hello', '--quiet']);
[, $out, $mail] = wpsecmon('integrity');
$html = mailHtml($mail);
expect('one e-mail for the administrator of both sites, with a copy', substr_count($mail, "\nSubject: ") === 1
    && strpos($mail, "To: admin@example.test\nCc: soc@example.test\n") === 0, $out . $mail);
expect('that e-mail reports both sites', has($html, ALICE) && has($html, BOB) && has($html, '2 sites checked'), $html);
// A changed address still gets the report that says so.
wp('alice', ALICE, ['option', 'update', 'admin_email', 'owner@alice.test', '--quiet']);
// Under systemd the unit sends the e-mails after the check, as it delivers the logs.
putenv('WP_SECMON_DEFER_DELIVERY=1');
[, $out, $mail] = wpsecmon('integrity');
putenv('WP_SECMON_DEFER_DELIVERY');
expect('e-mails queued when delivery is deferred', $mail === '' && count(glob('/var/lib/wp-secmon/mail/*.json') ?: []) === 2, $out . $mail);
[$code] = sh(['wp-secmon', '__deliver']);
$mail = (string) @file_get_contents(MAIL);
expect('queued e-mails sent after the check', $code === 0 && glob('/var/lib/wp-secmon/mail/*.json') === [], $mail);
expect('address change reported to the old and the new address', substr_count($mail, "\nSubject: ") === 2
    && has($mail, "To: owner@alice.test\nCc: soc@example.test\n") && has($mail, "To: admin@example.test\nCc: soc@example.test\n")
    && substr_count($mail, 'Content-Type: text/plain') === 2 && !has($mail, 'To: root'), $out . $mail);
[$code, $out] = wpsecmon('doctor');
expect('doctor shows who is e-mailed', has($out, 'each site is reported to its WordPress administration address, with a copy to soc@example.test'), $out);
file_put_contents('/etc/wp-secmon/wp-secmon.ini', $ini);

// ---------------------------------------------------------------------------
step('logs of the accounts cannot be turned against root');
// Bob plants a symbolic link where his logs go: the copy is made as bob, so it cannot reach /etc/passwd.
sh(['runuser', '-u', 'bob', '--', 'mkdir', '-p', '/home/bob/logs/wp-secmon']);
sh(['runuser', '-u', 'bob', '--', 'ln', '-sfn', '/etc/passwd', '/home/bob/logs/wp-secmon/alerts.log']);
$passwd = hash_file('sha256', '/etc/passwd');
wp('bob', BOB, ['plugin', 'deactivate', 'hello', '--quiet']);
[$code, $out] = wpsecmon('integrity', '--no-mail', '--site', BOB);
clearstatcache();
expect('a symbolic link in the logs folder is replaced, not followed', $code === 0 && hash_file('sha256', '/etc/passwd') === $passwd
    && !is_link('/home/bob/logs/wp-secmon/alerts.log') && has((string) @file_get_contents('/home/bob/logs/wp-secmon/alerts.log'), 'deactivated'), $out);
// A folder others can write to could be swapped for theirs: refused, without failing the check.
chmod('/home/bob/logs', 0777);
wp('bob', BOB, ['plugin', 'activate', 'hello', '--quiet']);
[$code, $out] = wpsecmon('integrity', '--no-mail', '--site', BOB);
expect('a logs folder others can write to is refused', $code === 0 && has($out, 'the logs of bob could not be copied')
    && has($out, '/home/bob/logs must be a directory of bob that no other account can write to')
    && !has((string) file_get_contents('/home/bob/logs/wp-secmon/alerts.log'), '1 plugin(s) activated'), $out);
chmod('/home/bob/logs', 0700);
[$code, $out] = wpsecmon('integrity', '--no-mail', '--site', BOB);
expect('kept and delivered once fixed', has((string) file_get_contents('/home/bob/logs/wp-secmon/alerts.log'), '1 plugin(s) activated'), $out);
// Run by hand as root, the helper refuses: as root, it would pass its own checks anywhere.
[$code] = sh(['wp-secmon', '__write-logs'], false, (string) json_encode(['home' => '/root', 'path' => 'logs/wp-secmon', 'append' => "x\n",
    'files' => [], 'cap' => 1000]));
expect('the logs helper refuses to write as root', $code === 1 && !file_exists('/root/logs'));

// ---------------------------------------------------------------------------
step('French');
$ini = (string) file_get_contents('/etc/wp-secmon/wp-secmon.ini');
file_put_contents('/etc/wp-secmon/wp-secmon.ini', $ini . "[general]\nlanguage = fr\n");
[, $out] = wpsecmon('sites');
expect('language set in the configuration', has($out, 'COMPTE') && has($out, 'Non surveillés :'), $out);
[, $out] = wpsecmon('sites', '--lang', 'en');
expect('--lang overrides the configuration', has($out, 'CHECKED AS'), $out);
file_put_contents('/etc/wp-secmon/wp-secmon.ini', $ini);
[, $out, $mail] = wpsecmon('integrity', '--lang', 'fr', '--site', ALICE, '--print');
$html = mailHtml($mail);
expect('report in French', has($out, 'Que faire') && has($out, '2 fichiers exécutables dans le dossier uploads'), $out);
expect('e-mail in French', has($mail, 'Subject: [wp-secmon]') && has($html, '<html lang="fr">')
    && has($html, 'Tout le monde peut s’inscrire et obtenir le rôle « administrator »'), $html);

// ---------------------------------------------------------------------------
step('review files in uploads');
// A file alice cannot read: the review reads files as the site owner, never as root.
$secret = ALICE . '/wp-content/uploads/2026/09/secret.php';
put($secret, "<?php // root only\n", 'root');
chmod($secret, 0600);
// 30 lines: the first 15 are shown, "c" shows the rest.
$photo = ALICE . '/wp-content/uploads/2026/09/photo.php.jpg';
put($photo, "<?php phpinfo();\n" . str_repeat("// padding\n", 28) . "// last line\n", 'alice');
wpsecmon('integrity', '--no-mail', '--site', ALICE);
$accepted = '/var/lib/wp-secmon/sites/' . substr(hash('sha256', ALICE), 0, 12) . '/uploads-accepted.json';
$before = snapshot();
// photo.php.jpg: cat, then yes. secret.php: cannot be read, so no question. sucuri-cmd.php: no.
[$code, $out] = wpsecmonWithInput("c\ny\nn\n", 'review', '--site', ALICE);
$after = snapshot();
echo $out;
expect('review lists the files of the last check', $code === 0 && has($out, ALICE . ' (read as alice): 3 files to review'), $out);
expect('review shows the first lines', has($out, "  | <?php passthru(\$_GET['c']);") && has($out, '  | <?php phpinfo();')
    && has($out, '... 15 more lines (c: cat the whole file)'), $out);
expect('c shows the whole file', has($out, '  | // last line'), $out);
expect('review reads files as the site owner', has($out, "'alice' cannot read it") && !has($out, 'root only'), $out);
$list = json_decode((string) @file_get_contents($accepted), true) ?? [];
expect('review records the sha256 of the accepted file', array_keys($list) === ['wp-content/uploads/2026/09/photo.php.jpg']
    && $list['wp-content/uploads/2026/09/photo.php.jpg']['hash'] === hash_file('sha256', $photo), (string) json_encode($list));
expect('database and files untouched by the review', ($d = sameSnapshot($before, $after)) === '', $d);
[, , , $details] = wpsecmon('integrity', '--no-mail', '--site', ALICE);
expect('accepted file no longer reported', has($details, '2 executable file(s) in the uploads directory') && has($details, 'sucuri-cmd.php')
    && !has($details, 'photo.php.jpg') && has($details, 'wp-secmon review --site ' . ALICE), $details);
[, $out] = wpsecmonWithInput('', 'review', '--site', ALICE);
[, $all] = wpsecmonWithInput('', 'review', '--accepted', '--site', ALICE);
expect('review skips accepted files unless --accepted', has($out, '2 files to review') && has($all, '3 files to review'), $out . $all);
put($photo, "<?php system(\$_GET['c']);\n", 'alice');
[, , , $details] = wpsecmon('integrity', '--no-mail', '--site', ALICE);
expect('accepted file reported again once changed', has($details, '3 executable file(s) in the uploads directory')
    && (bool) preg_match('#photo\.php\.jpg \(\d+ bytes\), changed since it was accepted#', $details), $details);
// photo.php.jpg: no longer accepted. sucuri-cmd.php: skip.
[, $out] = wpsecmonWithInput("n\n\n", 'review', '--site', ALICE);
expect('acceptance withdrawn', has($out, 'changed since') && has($out, 'no longer accepted') && has($out, '0 files accepted, 1 no longer accepted')
    && json_decode((string) file_get_contents($accepted), true) === [], $out);
unlink($secret);

// ---------------------------------------------------------------------------
step('an account runs wp-secmon itself');
/** Run wp-secmon as alice; returns [exit code, stdout+stderr, detailed reports in ~/.wp-secmon]. */
$asAlice = static function (string $input, string ...$args) use ($bin): array {
    @unlink(MAIL);
    foreach (glob('/home/alice/.wp-secmon/last-report-*.txt') ?: [] as $file) {
        unlink($file);
    }
    [$code, $out, $err] = sh(array_merge(['runuser', '-u', 'alice', '--', $bin], $args), false, $input);
    echo "\$ (alice) wp-secmon " . implode(' ', $args) . " (exit $code)\n";
    return [$code, $out . $err, implode('', array_map('file_get_contents', glob('/home/alice/.wp-secmon/last-report-*.txt') ?: []))];
};
$before = snapshot();
[$code, $out, $details] = $asAlice('', 'all');
echo $out;
$st = @stat('/home/alice/.wp-secmon');
expect('an account checks its own sites and prints the report', $code === 0 && has($out, 'What to do') && has($details, ALICE)
    && has($out, 'Details: /home/alice/.wp-secmon/last-report-') && !has($out . $details, 'Check failed'), $out . $details);
expect('nothing about the other accounts or the server', !has($out . $details, BOB) && !has($out . $details, ROOTSITE), $out . $details);
expect('its state is its own', $st && $st['uid'] === 1001 && ($st['mode'] & 0777) === 0700 && is_file('/home/alice/.wp-secmon/sites.json'));
expect('nothing e-mailed', !file_exists(MAIL));
[$code, $out] = $asAlice('', 'users', '--site', BOB);
expect("another account's site is not checked", $code === 1 && has($out, BOB . ': '), $out);
[, $out] = $asAlice('', 'sites');
expect('sites lists its own sites', (bool) preg_match('#^alice\s+http://alice\.test\s+owner@alice\.test\s+' . ALICE . '$#m', $out)
    && !has($out, BOB) && !has($out, ROOTSITE), $out);
[$code, $out] = $asAlice("y\ny\ny\n", 'review');
echo $out;
expect('an account reviews the files of its last check', $code === 0 && has($out, ALICE . ' (read as alice): ')
    && (bool) preg_match('/[1-9]\d* files? accepted/', $out) && has($out, "The server's own checks still report these files"), $out);
[, $out, $details] = $asAlice('', 'integrity');
expect('accepted files no longer reported to the account', has($out, 'Fixed since the last report')
    && !preg_match('/\[CRITICAL\] integrity: \d+ executable file/', $details), $out . $details);
$after = snapshot();
expect('database and files untouched by the account', ($d = sameSnapshot($before, $after)) === '', $d);
[, $out] = wpsecmon('status');
expect('files accepted by the account are still reported to root', has($out, 'executable file(s) in the uploads directory')
    && json_decode((string) file_get_contents($accepted), true) === [], $out);
[, $out] = $asAlice('', 'doctor');
expect('doctor for an account', has($out, "checks only the sites in this account's home") && has($out, 'reports are printed, not e-mailed')
    && has($out, 'state_dir /home/alice/.wp-secmon') && !has($out, '~/logs/wp-secmon'), $out);

// ---------------------------------------------------------------------------
step('site-users.map');
file_put_contents('/etc/wp-secmon/site-users.map', ROOTSITE . "  www-data\n" . BOB . "  root\n");
$generated = json_decode((string) file_get_contents('/var/lib/wp-secmon/sites.json'), true)['generated'];
[, $out] = wpsecmon('discover', '--site', ROOTSITE, '--site', BOB);
expect('discover --site examines only those sites', has($out, 'rediscovered 2 sites') && !has($out, 'discovery:'), $out);
expect('the site list keeps the date of the last full discovery',
    json_decode((string) file_get_contents('/var/lib/wp-secmon/sites.json'), true)['generated'] === $generated);
[, $out] = wpsecmon('sites');
echo $out;
expect('root-owned site mapped to www-data', (bool) preg_match('#^www-data\s+-\s+-\s+' . ROOTSITE . '$#m', $out), $out);
expect('mapping a site to root is refused', has($out, BOB . "\n      refusing to check a site as root"), $out);
expect('other sites untouched by the rediscovery, listed with their URL and administration e-mail',
    (bool) preg_match('#^alice\s+http://alice\.test\s+owner@alice\.test\s+' . ALICE . '$#m', $out), $out);
[, $out, , $details] = wpsecmon('users', '--print', '--site', ROOTSITE);
expect('mapped site checked as www-data', !has($out . $details, 'Check failed') && has($out, 'user baseline recorded'), $out);

step('rescan one site');
[$code, $out, , $details] = wpsecmon('all', '--print', '--no-mail', '--site', ROOTSITE);
expect('all --site rescans only that site', $code === 0 && has($out, 'rediscovered 1 site') && !has($out, 'discovery:')
    && has($out, 'finished discover, users, integrity, checksums, vulns: 1 site(s) checked'), $out);
expect('rescan reports on that site only', !has($details, ALICE) && !has($details, 'Check failed'), $details);
// www-data cannot create a folder in its home (/var/www on Debian, missing on EL), nor in a WordPress root.
expect('no logs where the account cannot write them', !file_exists('/var/www/logs') && !file_exists('/home/www-data')
    && !is_dir('/var/lib/wp-secmon/outbox/www-data'));

// ---------------------------------------------------------------------------
step('privilege guards');
sh(['groupadd', '-f', 'docker']);
sh(['useradd', '-m', '-u', '1003', '-G', 'docker', '-s', '/bin/bash', 'carol']);
fakeSite('/home/carol/public_html', 'carol');
// A site of alice's inside a directory of bob's: bob could swap it for his own code.
sh(['mkdir', '-p', '/home/bob/swap']);
sh(['chown', 'bob:bob', '/home/bob/swap']);
fakeSite('/home/bob/swap/site', 'alice');
// Alice's files, but www-data (PHP-FPM, say) can write to wp-content: it could drop a db.php there that would run as alice.
fakeSite('/home/alice/shop', 'alice');
mkdir('/home/alice/shop/wp-content');
chown('/home/alice/shop/wp-content', 'alice');
chgrp('/home/alice/shop/wp-content', 'www-data');
chmod('/home/alice/shop/wp-content', 0775);
// Writable by alice's own group only: fine.
fakeSite('/home/alice/team', 'alice');
chmod('/home/alice/team', 0775);
wpsecmon('discover');
[, $out] = wpsecmon('sites');
echo $out;
expect('member of a root-equivalent group is refused', has($out, "/home/carol/public_html\n      refusing to check a site as 'carol': member of docker"), $out);
expect('site another account could swap is refused', has($out, "/home/bob/swap/site\n      /home/bob belongs to 'bob'"), $out);
expect('site whose code another account can change is refused', has($out, "/home/alice/shop\n      /home/alice/shop/wp-content is writable by the group"
    . " 'www-data', which is not private to 'alice', so another account could change the code that would run as 'alice'"), $out);
expect('site writable by its own group is monitored', (bool) preg_match('#^alice\s+-\s+-\s+/home/alice/team$#m', $out), $out);

// Site code runs in a session of its own, so it cannot reach the terminal of an
// admin running wp-secmon by hand; and a flood of output is cut short.
put(ALICE . '/wp-config.php', "\n@file_put_contents('/tmp/wp-sid', explode(' ', (string) @file_get_contents('/proc/self/stat'))[5] ?? '');\n"
    . "if (file_exists('/tmp/flood')) { for (\$i = 0; \$i < 40; \$i++) { echo str_repeat('x', 1048576); } }\n", 'alice', true);
@unlink('/tmp/wp-sid');
wpsecmon('users', '--no-mail', '--site', ALICE);
$sid = trim((string) @file_get_contents('/tmp/wp-sid'));
expect('site code runs in a new session', $sid !== '' && $sid !== sessionId(), $sid);
touch('/tmp/flood');
[, $out] = wpsecmon('users', '--print', '--no-mail', '--site', ALICE);
unlink('/tmp/flood');
expect('output flood stopped and reported', has($out, 'wp user list failed: too much output'), $out);

// WP-CLI loads the object-cache.php drop-in, but not under the guard: like a must-use plugin, it could hide accounts.
put(ALICE . '/wp-content/object-cache.php', "<?php\n@touch('/tmp/object-cache-ran');\n", 'alice');
wp('alice', ALICE, ['option', 'get', 'siteurl']);
$loaded = file_exists('/tmp/object-cache-ran');
@unlink('/tmp/object-cache-ran');
[, $out] = wpsecmon('users', '--print', '--no-mail', '--site', ALICE);
expect('the object-cache.php drop-in is not loaded', $loaded && !file_exists('/tmp/object-cache-ran') && has($out, '1 site(s) checked, 0 error(s)'),
    'loaded without the guard: ' . var_export($loaded, true) . ', with it: ' . var_export(file_exists('/tmp/object-cache-ran'), true) . "\n$out");
unlink(ALICE . '/wp-content/object-cache.php');

step('update');
// A newer release, served locally in the GitHub API format.
sh(['cp', '-a', '/src', '/root/next']);
$boot = '/root/next/src/bootstrap.php';
file_put_contents($boot, preg_replace("/const VERSION = '[^']+'/", "const VERSION = '99.0.0'", (string) file_get_contents($boot)));
sh(['php', '-d', 'phar.readonly=0', '/root/next/build.php']);
mkdir('/root/release');
copy('/root/next/dist/wp-secmon.phar', '/root/release/wp-secmon.phar');
copy('/root/next/dist/wp-secmon.phar.sha256', '/root/release/wp-secmon.phar.sha256');
$publish = static function (string $tag): void {
    $assets = [];
    foreach (['wp-secmon.phar', 'wp-secmon.phar.sha256'] as $name) {
        $assets[] = ['name' => $name, 'browser_download_url' => "http://127.0.0.1:8099/$name"];
    }
    file_put_contents('/root/release/latest.json', json_encode(['tag_name' => $tag, 'assets' => $assets]));
};
$publish('v99.0.0');
$server = proc_open(['php', '-S', '127.0.0.1:8099', '-t', '/root/release'],
    [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', 8099); $i++) {
    usleep(100000);
}
file_put_contents('/etc/wp-secmon/wp-secmon.ini', "[update]\nupdate_url = \"http://127.0.0.1:8099/latest.json\"\n", FILE_APPEND);
$version = static function () use ($bin): string {
    return trim(sh([$bin, '--version'])[1]);
};

[$code, $out] = wpsecmon('update', '--check');
expect('update --check sees the new release', $code === 0 && has($out, 'wp-secmon 99.0.0 is available (this is ' . VERSION . ')'), $out);
$lock = fopen('/var/lib/wp-secmon/locks/vulns.lock', 'c');
flock($lock, LOCK_EX);
[$code, $out] = wpsecmon('update');
flock($lock, LOCK_UN);
fclose($lock);
expect('update waits until no check is running', $code !== 0 && has($out, "a 'vulns' run is in progress") && $version() === 'wp-secmon ' . VERSION, $out);
[$code, $out] = wpsecmon('update');
expect('update installs the new release', $code === 0 && has($out, 'wp-secmon updated from ' . VERSION . ' to 99.0.0') && $version() === 'wp-secmon 99.0.0', $out);
$st = stat($bin);
expect('updated program is root-owned and not writable by others', $st['uid'] === 0 && ($st['mode'] & 0777) === 0755);
expect('update keeps the configuration', has($out, 'kept /etc/wp-secmon/wp-secmon.ini') && has((string) file_get_contents('/etc/wp-secmon/wp-secmon.ini'), 'fake-sendmail'), $out);
[$code, $out] = wpsecmon('update');
expect('nothing to update', $code === 0 && has($out, 'wp-secmon 99.0.0 is up to date'), $out);
$publish('v99.0.1');
file_put_contents('/root/release/wp-secmon.phar', 'tampered', FILE_APPEND);
[$code, $out] = wpsecmon('update');
expect('update refuses a phar that does not match its checksum', $code !== 0 && has($out, 'checksum mismatch') && $version() === 'wp-secmon 99.0.0', $out);
proc_terminate($server);
proc_close($server);

step('upgrade from /usr/local/sbin');
// Where older versions installed the program.
rename($bin, '/usr/local/sbin/wp-secmon');
[$code, $out] = sh(['php', '/root/wp-secmon.phar', 'install']);
expect('the program moves to /usr/local/bin', is_file($bin) && !is_link($bin) && $version() === 'wp-secmon ' . VERSION
    && has($out, "program: $bin (moved from /usr/local/sbin/wp-secmon, which now links to it)") && !has($out, 'Next steps'), $out);
expect('a link to it stays at the old path', @readlink('/usr/local/sbin/wp-secmon') === $bin
    && trim(sh(['/usr/local/sbin/wp-secmon', '--version'])[1]) === 'wp-secmon ' . VERSION);

step('uninstall');
sh(['wp-secmon', 'uninstall']);
expect('uninstall removes the program and keeps the configuration', !file_exists($bin) && !is_link('/usr/local/sbin/wp-secmon')
    && is_file('/etc/wp-secmon/wp-secmon.ini'));
sh(['php', '/root/wp-secmon.phar', 'uninstall', '--purge']);
expect('--purge removes configuration, state and logs', !is_dir('/etc/wp-secmon') && !is_dir('/var/lib/wp-secmon') && !is_dir('/var/log/wp-secmon'));
expect('sites untouched by uninstall', is_file(ALICE . '/wp-config.php') && is_file(BOB . '/wp-load.php'));
expect('the accounts keep their logs', is_file(ALICE_LOGS . '/alerts.log'));

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
