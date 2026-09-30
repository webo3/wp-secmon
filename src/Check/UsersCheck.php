<?php

declare(strict_types=1);

namespace WpSecMon\Check;

use WpSecMon\I18n;
use WpSecMon\Log;
use WpSecMon\Site;
use WpSecMon\Util;

/**
 * users: detect account creation, deletion and privilege changes.
 *
 * `wp user list` is normalized and hashed; when the checksum differs from the
 * baseline the lists are compared and the changes reported. The new list then
 * becomes the baseline.
 */
final class UsersCheck extends Check
{
    public static function name(): string
    {
        return 'users';
    }

    protected function checkSite(Site $site): void
    {
        $wp = $this->ctx->wp;
        $alerts = $this->ctx->alerts;

        $ms = $wp->run($site, ['config', 'get', 'MULTISITE']);
        $multisite = $ms->ok() && in_array(strtolower(trim($ms->stdout)), ['1', 'true'], true);

        $args = ['user', 'list', '--fields=ID,user_login,user_email,roles,user_registered', '--format=json'];
        if ($multisite) {
            $args[] = '--network';
        }
        $r = $wp->run($site, $args);
        $list = $r->json();
        if ($list === null) {
            $alerts->siteError('users', I18n::t('wp user list failed: %s', $r->reason()), $r->details());
            return;
        }
        $supers = [];
        if ($multisite) {
            $sa = $wp->run($site, ['super-admin', 'list']);
            if ($sa->ok()) {
                $supers = array_values(array_filter(array_map('trim', explode("\n", $sa->stdout)), 'strlen'));
            }
        }
        $alerts->siteOk('users');

        $users = self::normalize($list, $supers);
        $json = Util::json($users) . "\n";
        $sum = hash('sha256', $json);
        $dir = $this->ctx->siteDir($site);
        $old = Util::readJson("$dir/users.json");

        if ($old !== null && trim((string) @file_get_contents("$dir/users.sha256")) === $sum) {
            Log::debug("{$site->root}: user list unchanged");
            return;
        }
        if ($old === null) {
            $priv = count(array_filter($users, function ($u) {
                return self::isPrivileged($u, $this->ctx->cfg->list('privileged_roles'));
            }));
            Log::info(I18n::t('%s: user baseline recorded (%d accounts, %d privileged)', $site->root, count($users), $priv));
        } else {
            $events = self::diff(
                $old,
                $users,
                $this->ctx->cfg->list('privileged_roles'),
                $this->ctx->cfg->str('users_alert_new'),
                $this->ctx->cfg->str('users_new_severity')
            );
            foreach ($events as [$sev, $title, $lines, $kind]) {
                $alerts->event($sev, $title, $lines, ['kind' => $kind]);
            }
        }
        Util::writeFile("$dir/users.json", $json);
        Util::writeFile("$dir/users.sha256", $sum . "\n");
    }

    /** Stable, sorted form of `wp user list --format=json`. */
    public static function normalize(array $list, array $supers = []): array
    {
        $out = [];
        foreach ($list as $u) {
            if (!is_array($u)) {
                continue;
            }
            $roles = $u['roles'] ?? '';
            $roles = is_array($roles) ? $roles : explode(',', (string) $roles);
            $roles = array_values(array_unique(array_filter(array_map(static function ($r) {
                return trim((string) $r);
            }, $roles), 'strlen')));
            sort($roles);
            $login = (string) ($u['user_login'] ?? '');
            $out[] = [
                'id' => (string) ($u['ID'] ?? ''),
                'login' => $login,
                'email' => (string) ($u['user_email'] ?? ''),
                'roles' => $roles,
                'registered' => (string) ($u['user_registered'] ?? ''),
                'super' => in_array($login, $supers, true),
            ];
        }
        usort($out, static function ($a, $b) {
            return (int) $a['id'] <=> (int) $b['id'];
        });
        return $out;
    }

    public static function isPrivileged(array $u, array $privilegedRoles): bool
    {
        return !empty($u['super']) || (bool) array_intersect($u['roles'] ?? [], $privilegedRoles);
    }

    /**
     * Compare two normalized lists.
     * @return array<int, array{0: string, 1: string, 2: string[], 3: string}> [severity, title, detail lines, kind (see Report)]
     */
    public static function diff(array $old, array $new, array $privRoles, string $mode, string $newSev): array
    {
        $isPriv = static function (array $u) use ($privRoles): bool {
            return self::isPrivileged($u, $privRoles);
        };
        $who = static function (array $u): string {
            return I18n::t('%s <%s> (ID %s)', Util::oneLine($u['login']), Util::oneLine($u['email']), $u['id']);
        };
        $roles = static function (array $u): string {
            $list = $u['roles'] ? Util::oneLine(implode(', ', $u['roles'])) : I18n::t('no role');
            return !empty($u['super']) ? I18n::t('%s + super admin', $list) : $list;
        };

        $o = array_column($old, null, 'id');
        $n = array_column($new, null, 'id');
        $ev = $addedOther = $removedOther = $other = [];

        foreach ($n as $id => $u) {
            if (!isset($o[$id])) {
                if ($isPriv($u)) {
                    $ev[] = ['critical', I18n::t('New privileged account: %s (%s)', $u['login'], $roles($u)),
                        ['    ' . I18n::t('%s, registered %s', $who($u), $u['registered'])], 'admin-new'];
                } else {
                    $addedOther[] = $u;
                }
                continue;
            }
            $was = $o[$id];
            if ($was == $u) {
                continue;
            }
            $privChange = $isPriv($was) !== $isPriv($u) || (!empty($u['super']) && empty($was['super']));
            if ($privChange && $isPriv($u)) {
                $ev[] = ['critical', I18n::t('Account granted privileges: %s', $u['login']),
                    ["    {$who($u)}", '    ' . I18n::t('roles: %s -> %s', $roles($was), $roles($u))], 'admin-new'];
            } elseif ($privChange) {
                $ev[] = ['warning', I18n::t('Account lost privileges: %s', $u['login']),
                    ["    {$who($u)}", '    ' . I18n::t('roles: %s -> %s', $roles($was), $roles($u))], 'admin-lost'];
            }
            if ($was['login'] !== $u['login']) {
                $ev[] = ['warning', I18n::t('Account login renamed: %s -> %s', $was['login'], $u['login']),
                    ['    ' . I18n::t('%s, roles: %s', $who($u), $roles($u))], 'user-renamed'];
                continue;
            }
            if ($privChange) {
                continue;
            }
            if ($was['email'] !== $u['email'] && $isPriv($u)) {
                $ev[] = ['warning', I18n::t('Privileged account e-mail changed: %s', $u['login']),
                    ['    ' . I18n::t('before: %s', Util::oneLine($was['email'])), '    ' . I18n::t('after:  %s', Util::oneLine($u['email']))], 'admin-email'];
                continue;
            }
            $what = [];
            if ($was['roles'] !== $u['roles']) {
                $what[] = I18n::t('roles %s -> %s', $roles($was), $roles($u));
            }
            if ($was['email'] !== $u['email']) {
                $what[] = I18n::t('e-mail %s -> %s', Util::oneLine($was['email']), Util::oneLine($u['email']));
            }
            if ($was['registered'] !== $u['registered']) {
                $what[] = I18n::t('registered %s -> %s', $was['registered'], $u['registered']);
            }
            if (!empty($was['super']) !== !empty($u['super'])) {
                $what[] = I18n::t('super admin removed');
            }
            if ($what) {
                $other[] = '    ' . I18n::t('%s: %s', $who($u), implode('; ', $what));
            }
        }
        foreach ($o as $id => $u) {
            if (isset($n[$id])) {
                continue;
            }
            if ($isPriv($u)) {
                $ev[] = ['warning', I18n::t('Privileged account deleted: %s', $u['login']), ['    ' . I18n::t('%s, roles: %s', $who($u), $roles($u))], 'admin-lost'];
            } else {
                $removedOther[] = $u;
            }
        }

        if ($addedOther && $mode === 'all') {
            $lines = [];
            foreach (array_slice($addedOther, 0, 50) as $u) {
                $lines[] = '    ' . I18n::t('%s, role: %s, registered %s', $who($u), $roles($u), $u['registered']);
            }
            if (count($addedOther) > 50) {
                $lines[] = '    ' . I18n::t('... and %d more', count($addedOther) - 50);
            }
            $ev[] = [$newSev, I18n::n(count($addedOther), '%d new account(s) created', '%d new account(s) created', count($addedOther)), $lines, 'users-new'];
        }
        if ($removedOther) {
            $lines = [];
            foreach (array_slice($removedOther, 0, 50) as $u) {
                $lines[] = '    ' . I18n::t('%s, role: %s', $who($u), $roles($u));
            }
            if (count($removedOther) > 50) {
                $lines[] = '    ' . I18n::t('... and %d more', count($removedOther) - 50);
            }
            $ev[] = ['info', I18n::n(count($removedOther), '%d account(s) deleted', '%d account(s) deleted', count($removedOther)), $lines, 'users-other'];
        }
        if ($other) {
            $ev[] = ['info', I18n::n(count($other), '%d account(s) modified', '%d account(s) modified', count($other)), array_merge(array_slice($other, 0, 50),
                count($other) > 50 ? ['    ' . I18n::t('... and %d more', count($other) - 50)] : []), 'users-other'];
        }
        // Most severe first, otherwise in the order found.
        $rank = ['critical' => 0, 'warning' => 1, 'info' => 2];
        $keys = array_keys($ev);
        usort($keys, static function ($a, $b) use ($ev, $rank) {
            return [$rank[$ev[$a][0]] ?? 3, $a] <=> [$rank[$ev[$b][0]] ?? 3, $b];
        });
        return array_map(static function ($k) use ($ev) {
            return $ev[$k];
        }, $keys);
    }
}
