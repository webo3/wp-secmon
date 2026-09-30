# wp-secmon

Read-only security monitoring for the WordPress sites of a server.

wp-secmon finds every WordPress install on the server and checks each site on a schedule (systemd timers):

- new or deleted accounts and privilege changes;
- tampered core and plugin files;
- backdoors in the usual hiding places;
- risky settings;
- known vulnerabilities.

Each run e-mails one report to root. The e-mail is written for people, not for logs: for each site, a status, what to do in plain language (for example "Update 5 plugins with known security holes" or "Confirm that each new administrator is legitimate"), a table of the plugins and themes to update, and one line per finding. You can forward it to the site owner as is. Reports are in English or French (`language` setting). File lists, CVEs and other details stay in `/var/log/wp-secmon`.

It works on cPanel/CloudLinux/Imunify360 servers and on plain LAMP/LEMP servers. It ships as a single `wp-secmon.phar` and needs only PHP 7.4+, which is already there wherever WordPress runs, and WP-CLI, which the installer downloads if needed.

**Guarantees**

- **Read-only.** wp-secmon never modifies a site: no files, no database rows, no cron, no outgoing HTTP from WordPress. See [How it stays read-only](#how-it-stays-read-only).
- **Never root.** Every WP-CLI call and every file read inside a site runs as the site's owner, with `--skip-plugins --skip-themes`. wp-secmon refuses to run anything as root, or as an account that is as good as root (`sudo`, `docker`, `lxd`...), even when misconfigured. Site code never gets a terminal, so it cannot reach the shell of an admin running wp-secmon by hand.

## Checks

| Check | Timer | Detects |
|---|---|---|
| `users` | hourly | Administrator accounts (`privileged_roles`) created, deleted, renamed or modified, e-mail changes on them, and accounts granted or losing privileges. Other accounts are ignored unless `users_alert_new = all`. Based on `wp user list`, normalized and checksummed; the diff runs only when the checksum changes. |
| `integrity` | hourly | Changes to site URL, admin e-mail, registration and default role. Open registration with a powerful default role. Plugins and themes installed, removed, activated or deactivated. Changes to `wp-config.php`, `.htaccess`/`.user.ini`/`php.ini`, non-core PHP files in the site root and in `wp-content`, drop-ins and must-use plugins (sha256 baseline). Executable files in uploads (`.php`, `.phtml`, `x.php.jpg`...), except harmless PHP recognized by its content (see below) and files accepted with `wp-secmon review`. |
| `checksums` | daily | `wp core verify-checksums` and `wp plugin verify-checksums --all`. Reports modified core files, extra files in `wp-admin` and `wp-includes`, and modified wordpress.org plugins. |
| `vulns` | daily | Known vulnerabilities in the installed core, plugin and theme versions ([wpvulnerability.net](https://www.wpvulnerability.net), free, no API key). Plugins and themes closed on wordpress.org. Core missing security releases. |
| `discover` | daily | New or removed WordPress installs, and sites that cannot be monitored (for example, owned by root). |

### Severities

| Severity | Examples |
|---|---|
| **critical** | New administrator, account promoted to administrator, core file modified, PHP file in uploads, new must-use plugin, new non-core PHP file in the site root, site URL changed, open registration as administrator, vulnerability rated high/critical or with no fix available. |
| **warning** | Privileged account deleted or its e-mail changed, `wp-config.php` or `.htaccess` modified, plugin installed, activated or deactivated, medium or low vulnerability, a check that could not run. |
| **info** | Plugin or theme updated or removed, theme switched, problem resolved. |

A report is e-mailed when it contains at least one alert at `mail_min_severity` (default: warning). The e-mail is HTML with a plain-text version of the same summary. Set `mail_format = text` to get the full details in plain text instead. The full details of each report are also kept in `/var/log/wp-secmon/last-report-*.txt`, and every alert is written to `/var/log/wp-secmon/alerts.log` and to the journal.

**One-off changes** (a new admin, a modified `wp-config.php`) are reported once, and the new state becomes the baseline.

**Ongoing problems** (modified core files, known vulnerabilities, PHP in uploads) are reported when they appear or change. While they persist, they are repeated every `alert_repeat_hours`, or weekly for vulnerabilities. Once fixed, they are reported as resolved. `wp-secmon status` lists what is still open.

The first run records the baselines silently and reports only ongoing problems.

**Harmless PHP in uploads** is recognized by its content, never by its path alone, since an attacker can drop a file anywhere. This covers "Silence is golden" stubs, compiled Twig templates (WPML cache), and PHP that cannot run code: files whose first statement is an unconditional `exit` (Sucuri's logs and settings), and files that only return a literal value (dompdf's font metrics, `*.ufm.php`). The files are read with PHP's own tokenizer, so a comment or `?>` cannot hide code in front of the `exit`. A web shell with the same name, in the same folder, is still reported.

**Accepting files in uploads:** for other PHP files that plugins keep in uploads, `wp-secmon review` goes through the executable files found by the last `integrity` check, one at a time. It shows each file's size, SHA-256 and first lines, and asks whether to accept it. `c` prints the whole file, and `a` accepts the file and the rest of its folder. An accepted file is no longer reported until its content changes: its SHA-256 is compared on every check. Files are read as the site owner, never as root. `--site PATH` reviews only some sites. `--accepted` also shows the files accepted before; answer `n` to have one reported again.

**Reporting everything again:** `wp-secmon reset` forgets which problems were already reported, and clears the cached vulnerability data. The next run (`wp-secmon all`) reports every open problem again, with fresh data. The baselines are kept, so real changes are still detected. Use `--site PATH` to reset only some sites.

## Install

Requirements:

- Linux with systemd.
- util-linux (`setpriv`, `setsid`, `prlimit`), installed by default on mainstream distributions.
- PHP 7.4+ CLI with the `json` and `phar` extensions, and `curl` or `openssl`. `posix` is recommended; without it, wp-secmon uses `getent`.
- WP-CLI at `/usr/local/bin/wp` (or `wp_cli`). The installer downloads it when it is missing.
- A local MTA providing `/usr/sbin/sendmail`. Exim on cPanel works as is.

As root, on each server:

```sh
curl -fsSLO https://github.com/webo3/wp-secmon/releases/latest/download/wp-secmon.phar && php wp-secmon.phar install && rm wp-secmon.phar
```

This does the following:

- copies the phar to `/usr/local/sbin/wp-secmon`;
- creates `/etc/wp-secmon/wp-secmon.ini` and `/etc/wp-secmon/site-users.map`;
- installs a logrotate rule, the `wp-secmon@.service` template and five timers, and enables the timers (add `--no-enable` to skip that);
- downloads WP-CLI to `/usr/local/bin/wp` (or `wp_cli`) when nothing is there, and checks it against the SHA-512 published by WP-CLI. If the download fails, the install goes on and tells you to install WP-CLI yourself.

The timers run with the PHP binary that ran `install`, or the one given with `--php=PATH`. They pass `-d disable_functions=` so a hardened `php.ini` cannot disable `proc_open`.

Then run:

```sh
wp-secmon doctor                # requirements, user switching, WP-CLI, mail, API access, first sites
wp-secmon sites                 # discovers the sites on the first run, then lists them
wp-secmon all --no-mail         # records the baselines and prints the first report
```

**Upgrade:** `wp-secmon update` installs the latest release when it is newer, and `wp-secmon update --check` only tells you whether there is one (`wp-secmon doctor` also does). The update checks the phar against its published SHA-256, then runs the new phar's own `install` with the PHP binary of the timers. You can also upgrade by running the install command again. Either way:

- your configuration is kept, and the new defaults are written to `*.dist` next to it;
- timers stay enabled or disabled as they were, and only timers added by the new version are enabled;
- the upgrade refuses to run while a check is running, because replacing the phar would break it. Try again when the check has finished.

**Uninstall:** `wp-secmon uninstall`. Add `--purge` to also delete `/etc/wp-secmon`, `/var/lib/wp-secmon` and `/var/log/wp-secmon`. WP-CLI is left in place.

## Usage

```text
wp-secmon [options] <command>

  discover | users | integrity | checksums | vulns | all | sites | status | reset | doctor
  review [--accepted]
  install [--php=PATH] [--no-enable] | update [--check] | uninstall [--purge]

  -c, --config FILE   Configuration file (default /etc/wp-secmon/wp-secmon.ini)
  -s, --site PATH     Only check this WordPress root (repeatable); discover
                      and all then examine only this site again
  -n, --no-mail       Do not send e-mail
  -p, --print         Print the summary on stdout (default on a terminal)
      --lang CODE     Language: en or fr (default: language in wp-secmon.ini)
  -v, --verbose       Debug output
  -q, --quiet         Only warnings and errors
```

`wp-secmon sites` lists the discovered sites, the account each one is checked as, and why the others are not monitored. When there is no site list yet, it runs the discovery first.

**Rescanning one site:** `wp-secmon all --site /home/alice/public_html` examines that site again (after a change to `site-users.map`, for example) and runs every check on it, without searching the whole server. It reports only on that site. `wp-secmon discover --site PATH` only updates the site list. Either way, a site must already be in the list: run `wp-secmon discover` to find new ones.

If the CLI `php.ini` disables `proc_open`, run manual commands as `php -d disable_functions= /usr/local/sbin/wp-secmon <command>`. The timers already do this.

To change a schedule, use `systemctl edit wp-secmon-users.timer`. For example, to check accounts every 15 minutes:

```ini
[Timer]
OnCalendar=
OnCalendar=*:0/15
```

## Configuration

Every setting is documented in [`resources/etc/wp-secmon.ini`](resources/etc/wp-secmon.ini), which is installed as `/etc/wp-secmon/wp-secmon.ini`. The settings you are most likely to change:

- `language`: `en` (default) or `fr`. The reports, the e-mails and the command output are in this language; `--lang` overrides it for one command. After a change, open problems are reported once more, in the new language.
- `scan_paths[]`: where to look for WordPress installs (default `/home`). Add `/var/www` or `/srv/www` on LEMP/LAMP servers.
- `alert_email`: default `root`. On cPanel, root's mail goes to the server contact address.
- `privileged_roles[]`: only these accounts are reported (default `administrator`, plus network super admins). Add `editor` or `shop_manager` if you consider them privileged.
- `users_alert_new = all`: also report the other accounts created, deleted or modified. New ones are reported with `users_new_severity` (default `warning`).
- `alert_command`: also push each report to Slack, ntfy, a ticketing system, etc. The text summary arrives on stdin. The command runs as root and the report quotes text controlled by the sites, so pass it along as data, never evaluate it.

### Which account a site is checked as

- **cPanel / CloudLinux:** the site's cPanel account, automatically. Suspended accounts are skipped.
- **LEMP/LAMP, sites owned by a regular user or by `www-data`/`nginx`/`apache`:** that owner, automatically. Owners below `min_uid` must be listed in `allowed_system_users`.
- **Code owned by root** (PHP-FPM running as `www-data`): the site is reported as "not monitored" until you map it in `/etc/wp-secmon/site-users.map` or set `fallback_user`:

  ```text
  /var/www/example.com/public   www-data
  /var/www/old-copy             -
  ```

  A site is never checked as root, even when it is mapped to root.

A site is also not monitored, with the reason shown by `wp-secmon sites`, when:

- **The account is as good as root:** its primary group is root, or it belongs to the root group or to one of `forbidden_groups` (`sudo`, `wheel`, `docker`, `lxd`...). Map the site to another account.
- **Another account could swap the site:** every directory from `/` down to the WordPress root must be a real directory (not a symbolic link) owned by root or by the site's account. The directories above the site must not be writable by other accounts; the account's own group and sticky directories such as `/tmp` are fine. Otherwise another account could replace the site with its own code between discovery and a check, and wp-secmon would run that code as the site's owner. The check is repeated before every WP-CLI call.

To switch users, wp-secmon uses `setpriv` (util-linux; no PAM session, `no_new_privs`), falling back to `runuser`, `sudo` or `su`. On CloudLinux, `run_as_method = cagefs` runs the checks inside the user's CageFS. WP-CLI and the PHP binary must then be available inside the cage.

## How it stays read-only

On the WP-CLI side:

- WP-CLI runs with `--skip-plugins --skip-themes --skip-packages --no-color` and `WP_CLI_CONFIG_PATH=/dev/null`. The user's own WP-CLI config, which can `require` arbitrary PHP, is ignored.
- A guard ([`resources/wordpress/readonly-guard.php`](resources/wordpress/readonly-guard.php)) is injected with `--exec` before WordPress boots. It:
  - drops every SQL statement that is not `SELECT`/`SHOW`/`DESCRIBE`/`EXPLAIN`/`SET`;
  - removes WP-Cron;
  - refuses outgoing HTTP from WordPress;
  - keeps must-use plugins from loading. `--skip-plugins` does not cover them, and a malicious one could hide accounts from `wp user list`.
- Update checks (which rewrite transients) are never triggered. The inventory is read with a small `wp eval` snippet ([`resources/wordpress/inventory.php`](resources/wordpress/inventory.php)).

On the file and process side:

- File hashing and the uploads scan run as the site owner, through the hidden `wp-secmon __scan-files` command. That command does not load WordPress ([`src/FileScanner.php`](src/FileScanner.php)).
- Discovery only lists directories and never follows symbolic links.
- Commands run without a shell (`proc_open` with an argument array), with a clean environment, `cwd=/`, no stdin and a timeout. Output goes to files, so a process left behind by site code cannot hang a run.
- Site code runs in a new session without a controlling terminal (`setsid`). Without `setsid`, wp-secmon refuses to check sites from a terminal.
- Each output file is capped at `max_output_mb` (`prlimit`), so a site cannot fill the disk or exhaust wp-secmon's memory and stop the report.
- The systemd service mounts `/home`, `/var/www` and `/srv` read-only for the whole process tree, WP-CLI included. It also uses `NoNewPrivileges`, `ProtectSystem=full` and `PrivateTmp`.

**Limits:**

- WP-CLI still executes `wp-config.php` and the `db.php`/`object-cache.php` drop-ins. That code is under the site owner's control, so a fully compromised site could lie to WP-CLI. The file checks do not depend on WordPress, and they alert on any change to those files.
- Plugins that are not hosted on wordpress.org cannot be checksum-verified. They are only listed with `--verbose`.

## Files on a server

| Path | Content |
|---|---|
| `/usr/local/sbin/wp-secmon` | The phar (root-owned, mode 0755: site owners execute it for the file scan) |
| `/usr/local/bin/wp` | WP-CLI, when the installer downloaded it (root-owned, mode 0755) |
| `/etc/wp-secmon/wp-secmon.ini`, `site-users.map` | Configuration (root-owned and not writable by others, or wp-secmon refuses to run) |
| `/etc/systemd/system/wp-secmon@.service`, `wp-secmon-*.timer` | Service template and timers |
| `/var/lib/wp-secmon/sites.json` | Discovered sites, skipped sites and the reason |
| `/var/lib/wp-secmon/sites/<id>/` | Per-site baselines (`users.json`, `files.json`, `options.json`, `components.json`), executable files found in uploads and those accepted (`uploads-exec.json`, `uploads-accepted.json`), and open alerts |
| `/var/lib/wp-secmon/cache/` | Vulnerability data and the WordPress release list |
| `/var/log/wp-secmon/alerts.log` | Every alert raised |
| `/var/log/wp-secmon/last-report-*.txt` | Full details of the last report of each check (the e-mail is a summary) |

To reset the baselines of one site, delete its directory under `/var/lib/wp-secmon/sites/`. Its `site.json` file shows which site it is.

## Development

```text
Makefile              build and test: make help lists the targets
bin/wp-secmon         run from a source checkout
build.php             builds dist/wp-secmon.phar (make build)
src/                  the application (namespace WpSecMon)
resources/etc/        default configuration, site-users.map, logrotate rule
resources/lang/       translations
resources/systemd/    service template and timers
resources/wordpress/  PHP passed to WP-CLI (read-only guard, inventory)
tests/                unit and end-to-end tests
```

```sh
make build    # writes dist/wp-secmon.phar and dist/wp-secmon.phar.sha256
```

Messages are written in English in the code, through `I18n::t()` (and `n()` for plurals, see [`src/I18n.php`](src/I18n.php)). [`resources/lang/fr.php`](resources/lang/fr.php) maps each one to its French translation. `make test` fails when a message has no translation, when a translation is no longer used, or when the placeholders differ. To add a language, copy `fr.php`, add its code to `I18n::LANGUAGES` and to the `language` choices in [`src/Config.php`](src/Config.php), and give `I18n::n()` its plural rule if it differs from English.

```sh
make test     # unit tests: parsing, diffs, version matching, file scan, alerts, translations
make e2e      # end-to-end tests in Docker: Debian 12 with PHP 8.2, and AlmaLinux 8 with PHP 7.4 without posix
              # (make e2e-debian or make e2e-el8 runs only one)
```

The end-to-end test builds the phar and installs it. It then creates real sites owned by separate users and simulates attacks:

- admins created through WP-CLI and through raw SQL, including one with a terminal escape sequence in its name;
- a hijacked admin e-mail;
- open registration as administrator;
- a modified core file and plugin;
- web shells in `wp-admin`, the site root and uploads, plus an `x.php.jpg`;
- a must-use plugin that tries to hide an account;
- an account in the `docker` group, a site inside another account's directory, and a site that floods its output.

It checks that every attack is reported and that site code runs in a session of its own. It also checks that database checksums and file metadata are identical before and after each wp-secmon run, that the malicious mu-plugin never executed, and that uninstalling leaves the sites untouched.

## License

[MIT](LICENSE) © 2026 webO3
