<?php
/**
 * French translation (see src/I18n.php).
 *
 * English message => French. Plural messages: English singular => [singular,
 * plural]; French uses the singular for 0 and 1. Keep every %s/%d of the
 * English message (reorder them with %1$s, %2$s... if needed).
 * tests/unit.php checks that this file matches the messages in src/.
 */

return [
    // Month names, for dates
    'January' => 'janvier',
    'February' => 'février',
    'March' => 'mars',
    'April' => 'avril',
    'May' => 'mai',
    'June' => 'juin',
    'July' => 'juillet',
    'August' => 'août',
    'September' => 'septembre',
    'October' => 'octobre',
    'November' => 'novembre',
    'December' => 'décembre',
    'Jan' => 'janv.',
    'Feb' => 'févr.',
    'Mar' => 'mars',
    'Apr' => 'avr.',
    'Jun' => 'juin',
    'Jul' => 'juil.',
    'Aug' => 'août',
    'Sep' => 'sept.',
    'Oct' => 'oct.',
    'Nov' => 'nov.',
    'Dec' => 'déc.',

    // Shared
    '%s: %s' => '%s : %s',
    '... and %d more' => '... et %d autres',
    'cannot stat %s' => 'impossible de lire les attributs de %s',
    'cannot read %s' => 'impossible de lire %s',
    'unknown language %s (expected %s)' => 'langue inconnue %s (attendu : %s)',

    // Report
    'Resolved: %s' => 'Résolu : %s',
    'Still present: %s' => 'Toujours présent : %s',
    'critical' => 'critique',
    'warning' => 'avertissement',
    'info' => 'info',
    '%d critical' => ['%d critique', '%d critiques'],
    '%d warning' => ['%d avertissement', '%d avertissements'],
    '%d info' => ['%d info', '%d infos'],
    'high' => 'élevé',
    'medium' => 'moyen',
    'low' => 'faible',
    'none' => 'aucun',
    'unknown' => 'inconnu',
    'Action required' => 'Action requise',
    'Attention recommended' => 'Attention recommandée',
    'No action needed' => 'Aucune action requise',
    'wp-secmon report for %s (%s)' => 'Rapport wp-secmon pour %s (%s)',
    'Run started %s, took %ds. Sites checked: %d. Check errors: %d.' => 'Début : %s, durée : %d s. Sites vérifiés : %d. Erreurs de vérification : %d.',
    'Alerts: %d critical, %d warning, %d info.' => 'Alertes : %d critique(s), %d avertissement(s), %d info.',
    '(server)' => '(serveur)',
    '(checked as: %s)' => '(compte : %s)',
    'wp-secmon %s is read-only: it never modifies the sites it checks.' => 'wp-secmon %s fonctionne en lecture seule : il ne modifie jamais les sites qu’il vérifie.',
    'Alert history: %s   Open alerts: wp-secmon status' => 'Historique des alertes : %s   Alertes ouvertes : wp-secmon status',
    'Confirm that each new administrator listed below is legitimate. If nobody on your team created it, treat the site as hacked: delete the account, change every administrator password and have the site cleaned.'
        => 'Confirmez que chaque nouvel administrateur ci-dessous est légitime. Si personne de votre équipe ne l’a créé, considérez le site comme piraté : supprimez le compte, changez le mot de passe de chaque administrateur et faites nettoyer le site.',
    'The site address changed. If this was not planned, visitors may be sent to another site: restore the address in Settings > General and find out how it was changed.'
        => 'L’adresse du site a changé. Si ce n’était pas prévu, les visiteurs peuvent être envoyés vers un autre site : rétablissez l’adresse dans Réglages > Général et trouvez comment elle a été changée.',
    '%d file was changed or added in WordPress core. WordPress never does this by itself: it usually means the site was hacked. Reinstall the WordPress core files and look for other backdoors.' => [
        '%d fichier a été modifié ou ajouté dans le cœur de WordPress. WordPress ne fait jamais cela de lui-même : c’est généralement le signe d’un piratage. Réinstallez les fichiers du cœur de WordPress et cherchez d’autres portes dérobées.',
        '%d fichiers ont été modifiés ou ajoutés dans le cœur de WordPress. WordPress ne fait jamais cela de lui-même : c’est généralement le signe d’un piratage. Réinstallez les fichiers du cœur de WordPress et cherchez d’autres portes dérobées.',
    ],
    '%d WordPress core file is missing: reinstall the WordPress core files.' => [
        '%d fichier du cœur de WordPress est manquant : réinstallez les fichiers du cœur de WordPress.',
        '%d fichiers du cœur de WordPress sont manquants : réinstallez les fichiers du cœur de WordPress.',
    ],
    'Files of %s differ from the official version: reinstall it from wordpress.org and look for injected code.' => [
        'Les fichiers de l’extension %s diffèrent de la version officielle : réinstallez-la depuis wordpress.org et cherchez du code injecté.',
        'Les fichiers des extensions %s diffèrent de la version officielle : réinstallez-les depuis wordpress.org et cherchez du code injecté.',
    ],
    'New PHP files appeared where WordPress does not put them. Check that your team added them: unknown files there are often backdoors.'
        => 'De nouveaux fichiers PHP sont apparus là où WordPress n’en met pas. Vérifiez que votre équipe les a ajoutés : des fichiers inconnus à ces endroits sont souvent des portes dérobées.',
    'The uploads folder, which should only hold images and documents, contains %d PHP or script file. Have it reviewed and removed, and block PHP in that folder.' => [
        'Le dossier uploads, qui ne devrait contenir que des images et des documents, contient %d fichier PHP ou script. Faites-le examiner et supprimer, et bloquez PHP dans ce dossier.',
        'Le dossier uploads, qui ne devrait contenir que des images et des documents, contient %d fichiers PHP ou scripts. Faites-les examiner et supprimer, et bloquez PHP dans ce dossier.',
    ],
    'Anyone can register and get the "%s" role. Turn off "Anyone can register", or set "New User Default Role" to Subscriber (Settings > General).'
        => 'Tout le monde peut s’inscrire et obtenir le rôle « %s ». Décochez « Tout le monde peut s’inscrire », ou réglez « Rôle par défaut de tout nouvel utilisateur » à Abonné (Réglages > Général).',
    'Update WordPress %s to %s: this version has %d known security hole.' => [
        'Mettez à jour WordPress %s vers %s : cette version a %d faille de sécurité connue.',
        'Mettez à jour WordPress %s vers %s : cette version a %d failles de sécurité connues.',
    ],
    '%s or later' => '%s ou une version plus récente',
    'the latest version' => 'la dernière version',
    'Update WordPress %s to %s: this version no longer receives security fixes.' => 'Mettez à jour WordPress %s vers %s : cette version ne reçoit plus de correctifs de sécurité.',
    'Update WordPress %s to %s: it is a security and maintenance release.' => 'Mettez à jour WordPress %s vers %s : c’est une version de sécurité et de maintenance.',
    'Update %s with known security holes (see "Updates needed").' => 'Mettez à jour %s comportant des failles de sécurité connues (voir « Mises à jour nécessaires »).',
    'No fix exists yet for %s: remove or replace it.' => [
        'Aucun correctif n’existe encore pour %s : supprimez-le ou remplacez-le.',
        'Aucun correctif n’existe encore pour %s : supprimez-les ou remplacez-les.',
    ],
    'Replace %s: it was removed from wordpress.org and no longer gets security fixes.' => [
        'Remplacez %s : retiré de wordpress.org, il ne reçoit plus de correctifs de sécurité.',
        'Remplacez %s : retirés de wordpress.org, ils ne reçoivent plus de correctifs de sécurité.',
    ],
    'Delete the %s with known security holes if you do not use it, or update it: inactive code can still be attacked.' => [
        'Supprimez %s comportant des failles de sécurité connues si vous ne vous en servez pas, ou faites la mise à jour : le code inactif peut quand même être attaqué.',
        'Supprimez %s comportant des failles de sécurité connues si vous ne vous en servez pas, ou faites les mises à jour : le code inactif peut quand même être attaqué.',
    ],
    'WordPress %s is available (this site runs %s): plan the upgrade.' => 'WordPress %s est disponible (ce site utilise %s) : planifiez la mise à niveau.',
    'An administrator e-mail address changed: confirm it. Whoever controls that address can reset the password.'
        => 'L’adresse courriel d’un administrateur a changé : confirmez-la. Quiconque contrôle cette adresse peut réinitialiser le mot de passe.',
    'Sensitive files changed, such as wp-config.php, .htaccess or must-use plugins. Confirm that your team made these changes.'
        => 'Des fichiers sensibles ont changé, comme wp-config.php, .htaccess ou des extensions indispensables (mu-plugins). Confirmez que votre équipe a fait ces changements.',
    'Plugins or themes were installed, activated or deactivated: confirm that your team made these changes.'
        => 'Des extensions ou des thèmes ont été installés, activés ou désactivés : confirmez que votre équipe a fait ces changements.',
    'New accounts were created. This is normal on shops and membership sites; otherwise, look for spam sign-ups.'
        => 'De nouveaux comptes ont été créés. C’est normal sur les boutiques et les sites d’adhésion; sinon, cherchez des inscriptions indésirables.',
    'Confirm the account and setting changes listed below.' => 'Confirmez les changements de comptes et de réglages ci-dessous.',
    '%s and %d more' => '%s et %d autres',
    '%s and %s' => '%s et %s',
    '%d inactive plugin' => ['%d extension inactive', '%d extensions inactives'],
    '%d plugin' => ['%d extension', '%d extensions'],
    '%d inactive theme' => ['%d thème inactif', '%d thèmes inactifs'],
    '%d theme' => ['%d thème', '%d thèmes'],
    '%d site checked' => ['%d site vérifié', '%d sites vérifiés'],
    '%d needs action' => ['%d demande une action', '%d demandent une action'],
    'still open since %s' => 'ouvert depuis le %s',
    'M j' => 'j M',
    'no fix yet' => 'aucun correctif',
    'latest' => 'dernière',
    'replace' => 'remplacer',
    '%s (theme)' => '%s (thème)',
    "theme\x04inactive" => 'inactif',
    "plugin\x04inactive" => 'inactive',
    'no fix yet for %d issue' => ['pas encore de correctif pour %d faille', 'pas encore de correctif pour %d failles'],
    'closed on wordpress.org (%s)' => 'retrait de wordpress.org (%s)',
    'closed on wordpress.org' => 'retrait de wordpress.org',
    'wp-secmon security report for %s' => 'Rapport de sécurité wp-secmon pour %s',
    'checked as %s' => 'compte %s',
    'What to do' => 'Que faire',
    'Updates needed' => 'Mises à jour nécessaires',
    'NAME' => 'NOM',
    'INSTALLED' => 'INSTALLÉE',
    'UPDATE TO' => 'MÀJ VERS',
    'RISK' => 'RISQUE',
    'NOTE' => 'NOTE',
    'Other findings' => 'Autres constats',
    'Findings' => 'Constats',
    'Fixed since the last report' => 'Corrigé depuis le dernier rapport',
    'Server notes' => 'Notes sur le serveur',
    'Details: %s · Open alerts: wp-secmon status' => 'Détails : %s · Alertes ouvertes : wp-secmon status',
    'Security report for %s' => 'Rapport de sécurité pour %s',
    'Security report' => 'Rapport de sécurité',
    'F j, Y, H:i T' => 'j F Y, H:i T',
    'About the monitoring itself, for the administrator.' => 'Sur la surveillance elle-même, pour l’administrateur.',
    'Full details on %s: %s · Open alerts: wp-secmon status' => 'Détails complets sur %s : %s · Alertes ouvertes : wp-secmon status',
    'Plugin / theme' => 'Extension / thème',
    'Installed' => 'Installée',
    'Update to' => 'Mettre à jour vers',
    'Risk' => 'Risque',
    '(theme)' => '(thème)',

    // Alerts
    'Check failed: %s' => 'Échec de la vérification : %s',
    'finished %s: %d site(s) checked, %d error(s); alerts: %d critical, %d warning, %d info (%d unchanged not repeated)'
        => 'fin de %s : %d site(s) vérifié(s), %d erreur(s); alertes : %d critique(s), %d avertissement(s), %d info (%d inchangée(s) non répétée(s))',
    '%s: %s - %s, %s (%s)' => '%s : %s - %s, %s (%s)',
    'alert_command failed: %s' => 'échec d’alert_command : %s',
    'report sent to %s' => 'rapport envoyé à %s',
    'sending the report with %s failed: %s' => 'échec de l’envoi du rapport avec %s : %s',
    'report sent to %s with mail()' => 'rapport envoyé à %s avec mail()',
    'the report could not be e-mailed; it is kept in %s' => 'le rapport n’a pas pu être envoyé par courriel; il est conservé dans %s',

    // Checks
    '%s: no longer exists, skipped until the next discovery' => '%s : n’existe plus, ignoré jusqu’à la prochaine découverte',
    'internal error: %s' => 'erreur interne : %s',
    'cannot read the WordPress inventory: %s' => 'impossible de lire l’inventaire WordPress : %s',

    // users
    'wp user list failed: %s' => 'échec de wp user list : %s',
    '%s: user baseline recorded (%d accounts, %d privileged)' => '%s : état de référence des comptes enregistré (%d comptes, %d privilégiés)',
    '%s <%s> (ID %s)' => '%s <%s> (ID %s)',
    'no role' => 'aucun rôle',
    '%s + super admin' => '%s + super admin',
    'New privileged account: %s (%s)' => 'Nouveau compte privilégié : %s (%s)',
    '%s, registered %s' => '%s, inscrit le %s',
    'Account granted privileges: %s' => 'Privilèges accordés au compte : %s',
    'roles: %s -> %s' => 'rôles : %s -> %s',
    'Account lost privileges: %s' => 'Privilèges retirés au compte : %s',
    'Account login renamed: %s -> %s' => 'Identifiant de compte renommé : %s -> %s',
    '%s, roles: %s' => '%s, rôles : %s',
    'Privileged account e-mail changed: %s' => 'Courriel d’un compte privilégié modifié : %s',
    'before: %s' => 'avant : %s',
    'after:  %s' => 'après : %s',
    'roles %s -> %s' => 'rôles %s -> %s',
    'e-mail %s -> %s' => 'courriel %s -> %s',
    'registered %s -> %s' => 'inscription %s -> %s',
    'super admin removed' => 'super admin retiré',
    'Privileged account deleted: %s' => 'Compte privilégié supprimé : %s',
    '%s, role: %s, registered %s' => '%s, rôle : %s, inscrit le %s',
    '%d new account(s) created' => ['%d nouveau compte créé', '%d nouveaux comptes créés'],
    '%s, role: %s' => '%s, rôle : %s',
    '%d account(s) deleted' => ['%d compte supprimé', '%d comptes supprimés'],
    '%d account(s) modified' => ['%d compte modifié', '%d comptes modifiés'],

    // integrity
    'Open registration handing out a powerful role is a common way to keep access to a hacked site. See Settings > General.'
        => 'Une inscription ouverte qui donne un rôle puissant est un moyen courant de garder l’accès à un site piraté. Voir Réglages > Général.',
    '(not set)' => '(non défini)',
    '(empty)' => '(vide)',
    'Site address (siteurl) changed' => 'Adresse du site (siteurl) modifiée',
    'Home address (home) changed' => 'Adresse d’accueil (home) modifiée',
    'Administration e-mail address changed' => 'Adresse courriel d’administration modifiée',
    '"Anyone can register" setting changed' => 'Réglage « Tout le monde peut s’inscrire » modifié',
    'Default role for new accounts changed' => 'Rôle par défaut des nouveaux comptes modifié',
    'Network registration setting changed' => 'Réglage d’inscription du réseau modifié',
    'Active theme changed' => 'Thème actif modifié',
    'Active parent theme changed' => 'Thème parent actif modifié',
    "Anyone can register and new accounts get the '%s' role" => 'Tout le monde peut s’inscrire et les nouveaux comptes reçoivent le rôle « %s »',
    '(no name)' => '(sans nom)',
    '%s (active)' => '%s (active)',
    '%d plugin(s) installed' => ['%d extension installée', '%d extensions installées'],
    '%d plugin(s) activated' => ['%d extension activée', '%d extensions activées'],
    '%d plugin(s) deactivated' => ['%d extension désactivée', '%d extensions désactivées'],
    '%d plugin(s) removed' => ['%d extension supprimée', '%d extensions supprimées'],
    '%d plugin(s) changed version' => ['%d extension a changé de version', '%d extensions ont changé de version'],
    '%d theme(s) installed' => ['%d thème installé', '%d thèmes installés'],
    '%d theme(s) removed' => ['%d thème supprimé', '%d thèmes supprimés'],
    '%d theme(s) changed version' => ['%d thème a changé de version', '%d thèmes ont changé de version'],
    'file scan failed: %s' => 'échec de l’analyse des fichiers : %s',
    '%s: file baseline recorded (%d files)' => '%s : état de référence des fichiers enregistré (%d fichiers)',
    '(scan stopped after 2000 matches)' => '(analyse arrêtée après 2000 résultats)',
    '%d executable file(s) in the uploads directory (%s)' => [
        '%d fichier exécutable dans le dossier uploads (%s)',
        '%d fichiers exécutables dans le dossier uploads (%s)',
    ],
    '%s (%d bytes)' => ['%s (%d octet)', '%s (%d octets)'],
    '%s, changed since it was accepted' => '%s, modifié depuis son acceptation',
    'Once checked, accept the harmless ones with: wp-secmon review --site %s' => 'Une fois vérifiés, acceptez ceux qui sont sans danger avec : wp-secmon review --site %s',
    'Server configuration in the site root (.htaccess, .user.ini, php.ini)' => 'Configuration du serveur à la racine du site (.htaccess, .user.ini, php.ini)',
    'Non-core PHP files in the site root' => 'Fichiers PHP hors du cœur à la racine du site',
    'PHP or configuration files directly in wp-content' => 'Fichiers PHP ou de configuration directement dans wp-content',
    'Drop-ins (wp-content/*.php overriding core behaviour)' => 'Drop-ins (fichiers wp-content/*.php qui remplacent un comportement du cœur)',
    'Must-use plugins (loaded on every request, cannot be disabled)' => 'Extensions indispensables (mu-plugins : chargées à chaque requête, impossibles à désactiver)',
    '.htaccess or .user.ini files inside uploads' => 'Fichiers .htaccess ou .user.ini dans uploads',
    'added: %s' => 'ajouté : %s',
    'modified: %s' => 'modifié : %s',
    'removed: %s' => 'supprimé : %s',
    '%d added' => ['%d fichier ajouté', '%d fichiers ajoutés'],
    '%d modified' => ['%d fichier modifié', '%d fichiers modifiés'],
    '%d removed' => ['%d fichier supprimé', '%d fichiers supprimés'],

    // checksums
    'wp core verify-checksums failed: %s' => 'échec de wp core verify-checksums : %s',
    'modified' => 'modifié',
    'should not exist' => 'ne devrait pas exister',
    'missing' => 'manquant',
    'WordPress core files do not match the official checksums: %d modified, %d unexpected, %d missing'
        => 'Les fichiers du cœur de WordPress ne correspondent pas aux sommes de contrôle officielles : %d modifié(s), %d inattendu(s), %d manquant(s)',
    'wp plugin verify-checksums failed: %s' => 'échec de wp plugin verify-checksums : %s',
    "Plugin '%s' does not match the wordpress.org checksums (%d file(s))" => [
        'L’extension « %s » ne correspond pas aux sommes de contrôle de wordpress.org (%d fichier)',
        'L’extension « %s » ne correspond pas aux sommes de contrôle de wordpress.org (%d fichiers)',
    ],
    'checksum does not match' => 'somme de contrôle différente',
    'file was added' => 'fichier ajouté',
    'file is missing' => 'fichier manquant',

    // vulns
    'Vulnerability database unreachable (%s)' => 'Base de données de vulnérabilités inaccessible (%s)',
    '%d request(s) failed; cached data was used where available.' => [
        '%d requête a échoué; les données en cache ont été utilisées quand elles existaient.',
        '%d requêtes ont échoué; les données en cache ont été utilisées quand elles existaient.',
    ],
    'WordPress core %s' => 'Cœur de WordPress %s',
    'Plugin %s %s (%s, active)' => 'Extension %s %s (%s, active)',
    'Plugin %s %s (%s, inactive)' => 'Extension %s %s (%s, inactive)',
    'Theme %s %s (%s, active)' => 'Thème %s %s (%s, actif)',
    'Theme %s %s (%s, inactive)' => 'Thème %s %s (%s, inactif)',
    '%s was closed on wordpress.org (reason: %s)' => '%s : retrait de wordpress.org (raison : %s)',
    '%s was closed on wordpress.org' => '%s : retrait de wordpress.org',
    'A closed plugin or theme no longer receives updates, including security fixes.'
        => 'Une extension ou un thème retiré ne reçoit plus de mises à jour, y compris les correctifs de sécurité.',
    'severity: %s%s; %s' => 'risque : %s%s; %s',
    'NO FIX AVAILABLE' => 'AUCUN CORRECTIF DISPONIBLE',
    'fixed in %s' => 'correctif : %s',
    'update to the latest version' => 'mettez à jour vers la dernière version',
    '%s: %d known vulnerability' => ['%s : %d vulnérabilité connue', '%s : %d vulnérabilités connues'],
    'cannot fetch the WordPress release list; outdated core is not reported this run'
        => 'impossible de récupérer la liste des versions de WordPress; les versions périmées ne sont pas signalées cette fois-ci',
    'WordPress %s is missing the %s security/maintenance release' => 'Il manque à WordPress %s la version de sécurité et de maintenance %s',
    'Latest WordPress release: %s' => 'Dernière version de WordPress : %s',
    'WordPress %s is outdated and its branch no longer receives updates' => 'WordPress %s est périmé et sa branche ne reçoit plus de mises à jour',
    'WordPress %s is not the latest major release (%s)' => 'WordPress %s n’est pas la dernière version majeure (%s)',
    'unnamed vulnerability' => 'vulnérabilité sans nom',

    // Discovery and sites
    'no site list yet: searching the whole server first' => 'pas encore de liste de sites : recherche sur tout le serveur d’abord',
    'discovery: %d site(s), %d skipped, %d without wp-config.php (%.1fs)' => 'découverte : %d site(s), %d ignoré(s), %d sans wp-config.php (%.1f s)',
    "%s is not in the site list; run 'wp-secmon discover' to search for new sites" => '%s n’est pas dans la liste des sites; lancez « wp-secmon discover » pour chercher les nouveaux sites',
    'rediscovered %d site (%.1fs)' => ['%d site réexaminé (%.1f s)', '%d sites réexaminés (%.1f s)'],
    'WordPress install with control characters in its path was not checked' => 'Installation WordPress non vérifiée : son chemin contient des caractères de contrôle',
    'not a WordPress root (no wp-includes/version.php)' => 'pas une racine WordPress (pas de wp-includes/version.php)',
    'no wp-config.php' => 'pas de wp-config.php',
    'skipped in %s' => 'ignoré dans %s',
    'cannot stat the directory' => 'impossible de lire les attributs du dossier',
    'owned by root: map it in %s or set fallback_user' => 'appartient à root : associez-le à un compte dans %s ou réglez fallback_user',
    'owner uid %d has no account' => 'le propriétaire (uid %d) n’a pas de compte',
    "account '%s' does not exist" => 'le compte « %s » n’existe pas',
    'refusing to check a site as root' => 'refus de vérifier un site en tant que root',
    "owner '%s' (uid %d) is below min_uid; add it to allowed_system_users or map the site"
        => 'le propriétaire « %s » (uid %d) est sous min_uid; ajoutez-le à allowed_system_users ou associez le site à un compte',
    'cPanel account suspended' => 'compte cPanel suspendu',
    "owned by '%s'; run wp-secmon as root to check it" => 'appartient à « %s »; lancez wp-secmon en tant que root pour le vérifier',
    "refusing to check a site as '%s': %s; map it to another account" => 'refus de vérifier un site en tant que « %s » : %s; associez-le à un autre compte',
    "%s, so the site could be swapped for code that would run as '%s'" => '%s, donc le site pourrait être remplacé par du code qui s’exécuterait en tant que « %s »',
    '%s (checked as: %s)' => '%s (compte : %s)',
    '%d new WordPress install(s) found' => ['%d nouvelle installation WordPress trouvée', '%d nouvelles installations WordPress trouvées'],
    '%d WordPress install(s) no longer found' => ['%d installation WordPress disparue', '%d installations WordPress disparues'],
    'Site is not monitored: %s' => 'Site non surveillé : %s',

    // Running as site owners
    'no way to switch users: install util-linux (setpriv/runuser), sudo or su' => 'impossible de changer d’utilisateur : installez util-linux (setpriv/runuser), sudo ou su',
    'run_as_method=%s but %s is not installed' => 'run_as_method=%s mais %s n’est pas installé',
    'setsid(1) is required to check sites from a terminal: install util-linux, or let the systemd timers run the checks'
        => 'setsid(1) est requis pour vérifier des sites depuis un terminal : installez util-linux, ou laissez les timers systemd lancer les vérifications',
    'it is root' => 'c’est root',
    'its primary group is root' => 'son groupe principal est root',
    'cannot list its groups' => 'impossible de lister ses groupes',
    'member of the root group' => 'membre du groupe root',
    'member of %s (forbidden_groups)' => 'membre de %s (forbidden_groups)',
    '%s is a symbolic link or not a directory' => '%s est un lien symbolique ou n’est pas un dossier',
    "%s belongs to '%s'" => '%s appartient à « %s »',
    '%s is writable by other accounts' => '%s est modifiable par d’autres comptes',
    "unknown user '%s'" => 'utilisateur inconnu « %s »',
    "refusing to run a command as root (user '%s')" => 'refus d’exécuter une commande en tant que root (utilisateur « %s »)',
    'refusing to run as root' => 'refus de s’exécuter en tant que root',
    "not running as root, cannot switch to '%s'" => 'pas exécuté en tant que root, impossible de passer à « %s »',
    "refusing to run as '%s': %s" => 'refus de s’exécuter en tant que « %s » : %s',
    'timed out' => 'délai dépassé',
    'refused to run' => 'exécution refusée',
    'too much output (see max_output_mb)' => 'trop de sortie (voir max_output_mb)',
    'exit code %d' => 'code de sortie %d',

    // Configuration and files
    'configuration file not found: %s' => 'fichier de configuration introuvable : %s',
    'cannot parse %s: %s' => 'impossible d’analyser %s : %s',
    'syntax error' => 'erreur de syntaxe',
    "%s: unknown setting '%s' ignored" => '%s : réglage inconnu « %s » ignoré',
    '%s: invalid value for %s (expected %s)' => '%s : valeur invalide pour %s (attendu : %s)',
    'cannot create directory %s' => 'impossible de créer le dossier %s',
    '%s must be owned by root and not group/world writable (uid %d, mode %o)'
        => '%s doit appartenir à root et ne pas être modifiable par le groupe ou les autres (uid %d, mode %o)',

    // Command line
    'Usage: wp-secmon [options] <command>

Read-only security monitoring for the WordPress sites of this server.
Alerts are e-mailed to root (see alert_email in /etc/wp-secmon/wp-secmon.ini).

Commands:
  discover    Find WordPress installs and refresh the site list
  users       Accounts created or deleted, privilege and e-mail changes
  integrity   Options, plugins/themes, wp-config.php, .htaccess, mu-plugins,
              drop-ins, non-core PHP files and executables in uploads
  checksums   Core and wordpress.org plugin files against official checksums
  vulns       Known vulnerabilities, closed plugins, outdated core
  all         discover + users + integrity + checksums + vulns
  sites       List the discovered sites and the account each one is checked
              as (runs discovery first when there is no site list yet)
  status      Show open (unresolved) alerts
  review      Go through the executable files found in uploads and accept
              the harmless ones: an accepted file is no longer reported,
              until its content changes (use --site for some sites only)
                --accepted   Also go through the files accepted before
  reset       Forget open alerts and cached vulnerability data, so the next
              run reports every problem again (baselines are kept; use
              --site to reset only some sites)
  doctor      Check requirements and configuration

  install     Install this phar as /usr/local/sbin/wp-secmon, with its
              configuration, systemd timers and WP-CLI if missing
              (upgrades in place)
                --php=PATH   PHP binary for the timers (default: this one)
                --no-enable  Install the timers without enabling them
  update      Install the latest release of wp-secmon if it is newer
                --check      Only tell whether a newer release exists
  uninstall   Remove the program and timers
                --purge      Also delete configuration, state and logs

Options:
  -c, --config FILE   Configuration file (default /etc/wp-secmon/wp-secmon.ini)
  -s, --site PATH     Only check this WordPress root (repeatable). discover
                      and all then examine only this site again instead of
                      searching the server: wp-secmon all --site PATH rescans it
  -n, --no-mail       Do not send e-mail
  -p, --print         Print the summary on stdout (default on a terminal)
      --lang CODE     Language: en or fr (default: language in wp-secmon.ini)
  -v, --verbose       Debug output
  -q, --quiet         Only warnings and errors
  -V, --version       Show the version
  -h, --help          Show this help
' => 'Utilisation : wp-secmon [options] <commande>

Surveillance de sécurité en lecture seule des sites WordPress de ce serveur.
Les alertes sont envoyées par courriel à root (voir alert_email dans
/etc/wp-secmon/wp-secmon.ini).

Commandes :
  discover    Trouver les installations WordPress et mettre à jour la liste
              des sites
  users       Comptes créés ou supprimés, changements de privilèges et de
              courriel
  integrity   Réglages, extensions et thèmes, wp-config.php, .htaccess,
              mu-plugins, drop-ins, fichiers PHP hors du cœur et exécutables
              dans uploads
  checksums   Fichiers du cœur et des extensions de wordpress.org comparés
              aux sommes de contrôle officielles
  vulns       Vulnérabilités connues, extensions retirées, WordPress périmé
  all         discover + users + integrity + checksums + vulns
  sites       Lister les sites découverts et le compte utilisé pour chacun
              (lance d’abord la découverte s’il n’y a pas encore de liste)
  status      Afficher les alertes ouvertes (non résolues)
  review      Examiner les fichiers exécutables trouvés dans uploads et
              accepter ceux qui sont sans danger : un fichier accepté n’est
              plus signalé tant que son contenu ne change pas (--site pour
              certains sites seulement)
                --accepted    Examiner aussi les fichiers déjà acceptés
  reset       Oublier les alertes ouvertes et les données de vulnérabilités
              en cache, pour que la prochaine exécution signale de nouveau
              chaque problème (les états de référence sont conservés;
              --site pour ne réinitialiser que certains sites)
  doctor      Vérifier les prérequis et la configuration

  install     Installer ce phar comme /usr/local/sbin/wp-secmon, avec sa
              configuration, ses timers systemd et WP-CLI s’il manque
              (mise à niveau sur place)
                --php=CHEMIN  PHP utilisé par les timers (défaut : celui-ci)
                --no-enable   Installer les timers sans les activer
  update      Installer la dernière version de wp-secmon si elle est plus
              récente
                --check       Seulement indiquer si une version plus
                              récente existe
  uninstall   Retirer le programme et les timers
                --purge       Supprimer aussi la configuration, l’état et
                              les journaux

Options :
  -c, --config FICHIER  Configuration (défaut : /etc/wp-secmon/wp-secmon.ini)
  -s, --site CHEMIN     Vérifier seulement cette racine WordPress (répétable).
                        discover et all n’examinent alors que ce site, sans
                        fouiller le serveur : wp-secmon all --site CHEMIN le
                        revérifie
  -n, --no-mail         Ne pas envoyer de courriel
  -p, --print           Afficher le résumé (par défaut dans un terminal)
      --lang CODE       Langue : en ou fr (défaut : language dans wp-secmon.ini)
  -v, --verbose         Messages de débogage
  -q, --quiet           Seulement les avertissements et les erreurs
  -V, --version         Afficher la version
  -h, --help            Afficher cette aide
',
    'option %s needs a value' => 'l’option %s demande une valeur',
    'unknown option %s (see --help)' => 'option inconnue %s (voir --help)',
    'unexpected argument %s' => 'argument inattendu %s',
    'proc_open is disabled in php.ini; run: %s' => 'proc_open est désactivé dans php.ini; lancez : %s',
    "unknown command '%s' (see --help)" => 'commande inconnue « %s » (voir --help)',
    'not running as root: only sites owned by the current user can be checked' => 'pas exécuté en tant que root : seuls les sites de l’utilisateur courant peuvent être vérifiés',
    "another '%s' run is in progress, skipped" => 'une autre exécution de « %s » est en cours, ignorée',
    'WP-CLI is not usable, see: wp-secmon doctor' => 'WP-CLI n’est pas utilisable, voir : wp-secmon doctor',
    'no site list yet: discovering the WordPress installs first' => 'pas encore de liste de sites : découverte des installations WordPress d’abord',
    'No WordPress install found in %s.' => 'Aucune installation WordPress trouvée dans %s.',
    "Add the directories that hold the sites to scan_paths in %s, then run 'wp-secmon discover'."
        => 'Ajoutez les dossiers qui contiennent les sites à scan_paths dans %s, puis lancez « wp-secmon discover ».',
    'Discovered %s: %d monitored, %d skipped, %d without wp-config.php' => 'Découverte du %s : %d surveillé(s), %d ignoré(s), %d sans wp-config.php',
    'CHECKED AS' => 'COMPTE',
    'WORDPRESS ROOT' => 'RACINE WORDPRESS',
    'Not monitored:' => 'Non surveillés :',
    'WordPress files without wp-config.php (old copies?):' => 'Fichiers WordPress sans wp-config.php (anciennes copies?) :',
    'No open alerts.' => 'Aucune alerte ouverte.',
    'SEVERITY' => 'GRAVITÉ',
    'SINCE' => 'DEPUIS',
    'CHECK' => 'VÉRIFICATION',
    'SITE' => 'SITE',
    'ALERT' => 'ALERTE',
    'Nothing to reset: %s does not exist yet.' => 'Rien à réinitialiser : %s n’existe pas encore.',
    "a '%s' run is in progress; try again when it has finished" => 'une exécution de « %s » est en cours; réessayez quand elle sera terminée',
    '%s: no monitoring state for this site (never checked?)' => '%s : aucun état de surveillance pour ce site (jamais vérifié?)',
    'Forgot %d open alert(s) and the cached vulnerability data. Baselines are kept.' => [
        '%d alerte ouverte oubliée, ainsi que les données de vulnérabilités en cache. Les états de référence sont conservés.',
        '%d alertes ouvertes oubliées, ainsi que les données de vulnérabilités en cache. Les états de référence sont conservés.',
    ],
    'Forgot %d open alert(s) on %d site(s) and the cached vulnerability data. Baselines are kept.' => [
        '%d alerte ouverte oubliée sur %d site(s), ainsi que les données de vulnérabilités en cache. Les états de référence sont conservés.',
        '%d alertes ouvertes oubliées sur %d site(s), ainsi que les données de vulnérabilités en cache. Les états de référence sont conservés.',
    ],
    "Run 'wp-secmon all' to report every problem again." => 'Lancez « wp-secmon all » pour signaler de nouveau chaque problème.',

    // review
    'Nothing to review: the last integrity check found no executable file to accept in uploads.'
        => 'Rien à examiner : la dernière vérification d’intégrité n’a trouvé aucun fichier exécutable à accepter dans uploads.',
    '%s (read as %s): %d file to review' => ['%s (lu en tant que %s) : %d fichier à examiner', '%s (lu en tant que %s) : %d fichiers à examiner'],
    'Accept this file? [y]es, [n]o, [a]ll of this folder, [c]at the whole file, [q]uit, Enter: skip'
        => 'Accepter ce fichier ? [y] oui, [n] non, [a] tout ce dossier, [c] afficher tout le fichier, [q] quitter, Entrée : passer',
    'it changed since it was shown; its current version:' => 'il a changé depuis son affichage; sa version actuelle :',
    'accepted' => 'accepté',
    'accepted with the rest of its folder' => 'accepté avec le reste de son dossier',
    'no longer accepted: it will be reported again' => 'n’est plus accepté : il sera de nouveau signalé',
    'cannot read it: %s' => 'lecture impossible : %s',
    'no longer there' => 'n’existe plus',
    'it changed while being read: review it again' => 'modifié pendant la lecture : examinez-le de nouveau',
    "'%s' cannot read it" => '« %s » ne peut pas le lire',
    'symbolic link to %s' => 'lien symbolique vers %s',
    '%d byte' => ['%d octet', '%d octets'],
    '%s, modified %s' => '%s, modifié le %s',
    'accepted on %s' => 'accepté le %s',
    'accepted on %s, changed since' => 'accepté le %s, modifié depuis',
    '... %d more line (c: cat the whole file)' => ['... %d ligne de plus (c : afficher tout le fichier)', '... %d lignes de plus (c : afficher tout le fichier)'],
    '... (c: cat the whole file)' => '... (c : afficher tout le fichier)',
    '... only the first %d MB are shown' => '... seuls les %d premiers Mo sont affichés',
    '(binary content, not shown)' => '(contenu binaire, non affiché)',
    '%d file accepted' => ['%d fichier accepté', '%d fichiers acceptés'],
    '%d no longer accepted' => ['%d n’est plus accepté', '%d ne sont plus acceptés'],
    "The next integrity check takes this into account (hourly, or now with 'wp-secmon integrity')."
        => 'La prochaine vérification d’intégrité en tient compte (toutes les heures, ou maintenant avec « wp-secmon integrity »).',

    // doctor
    'WP-CLI not found at %s (set wp_cli)' => 'WP-CLI introuvable à %s (réglez wp_cli)',
    '%s is not executable (chmod 755 it or set wp_php)' => '%s n’est pas exécutable (faites chmod 755 ou réglez wp_php)',
    'WP-CLI: %s' => 'WP-CLI : %s',
    'Environment' => 'Environnement',
    '%s: the timers run it as root' => '%s : les timers systemd l’exécutent en tant que root',
    'disabled in php.ini: %s (run with: %s -d disable_functions= ...)' => 'désactivé dans php.ini : %s (lancez avec : %s -d disable_functions= ...)',
    'proc_open is available' => 'proc_open est disponible',
    'json extension' => 'extension json',
    'posix extension' => 'extension posix',
    'posix extension missing (install php-process / php-posix); falling back to getent' => 'extension posix absente (installez php-process / php-posix); getent est utilisé à la place',
    'tokenizer extension' => 'extension tokenizer',
    'tokenizer extension missing: harmless PHP data files in uploads (Sucuri, dompdf fonts) are reported'
        => 'extension tokenizer absente : les fichiers de données PHP sans danger dans uploads (Sucuri, polices dompdf) sont signalés',
    'HTTPS client (curl or openssl extension)' => 'client HTTPS (extension curl ou openssl)',
    'open_basedir is set for the CLI; run with -d open_basedir=' => 'open_basedir est défini pour le CLI; lancez avec -d open_basedir=',
    'no open_basedir restriction' => 'aucune restriction open_basedir',
    'running as root' => 'exécuté en tant que root',
    'not running as root: only your own sites can be checked' => 'pas exécuté en tant que root : seuls vos propres sites peuvent être vérifiés',
    'configuration: %s' => 'configuration : %s',
    'no configuration file at %s, using defaults' => 'aucun fichier de configuration à %s, valeurs par défaut utilisées',
    'language: %s' => 'langue : %s',
    'Running as site owners' => 'Exécution en tant que propriétaires des sites',
    'user switching: %s (no PAM session, no_new_privs)' => 'changement d’utilisateur : %s (sans session PAM, no_new_privs)',
    'user switching: %s' => 'changement d’utilisateur : %s',
    'timeout(1) available' => 'timeout(1) disponible',
    'timeout(1) missing; relying on the internal timeout' => 'timeout(1) absent; le délai interne est utilisé',
    'prlimit(1) available: output capped at %d MB' => 'prlimit(1) disponible : sortie limitée à %d Mo',
    'prlimit(1) missing (util-linux): a site can fill the disk until wp_timeout' => 'prlimit(1) absent (util-linux) : un site peut remplir le disque jusqu’à wp_timeout',
    '%s (phar)' => '%s (phar)',
    '%s (source tree)' => '%s (sources)',
    'program: %s' => 'programme : %s',
    'program: %s must be owned by root and not group/world writable: site owners execute it'
        => 'programme : %s doit appartenir à root et ne pas être modifiable par le groupe ou les autres : les propriétaires des sites l’exécutent',
    'Alerts and storage' => 'Alertes et stockage',
    'mail to %s via %s' => 'courriel à %s via %s',
    '%s not found, using PHP mail()' => '%s introuvable, PHP mail() est utilisé',
    '%s not found' => '%s introuvable',
    '%s %s is not writable' => '%s %s n’est pas accessible en écriture',
    '%s reachable' => '%s accessible',
    '%s unreachable (outdated core not reported)' => '%s inaccessible (versions de WordPress périmées non signalées)',
    '%s unreachable (vulnerabilities not reported)' => '%s inaccessible (vulnérabilités non signalées)',
    'Timers' => 'Timers systemd',
    'Sites' => 'Sites',
    "no site list yet: run 'wp-secmon discover'" => 'pas encore de liste de sites : lancez « wp-secmon discover »',
    '%d monitored, %d skipped (see wp-secmon sites)' => '%d surveillé(s), %d ignoré(s) (voir wp-secmon sites)',
    '%s as %s: %s' => '%s avec le compte %s : %s',
    '(first 5 sites tested; use --site PATH to test another)' => '(5 premiers sites testés; utilisez --site CHEMIN pour en tester un autre)',
    '%d problem(s), %d warning(s).' => '%d problème(s), %d avertissement(s).',

    // install / uninstall
    'wp-secmon runs on Linux servers' => 'wp-secmon fonctionne sur les serveurs Linux',
    'run the installer as root' => 'lancez l’installation en tant que root',
    '%s failed: %s' => 'échec de %s : %s',
    'install from the phar: php -d phar.readonly=0 build.php && php dist/wp-secmon.phar install'
        => 'installez à partir du phar : php -d phar.readonly=0 build.php && php dist/wp-secmon.phar install',
    'PHP binary not found: %s' => 'binaire PHP introuvable : %s',
    '%s: the timers run it as root (choose another with --php=)' => '%s : les timers systemd l’exécutent en tant que root (choisissez-en un autre avec --php=)',
    '%s is not PHP 7.4 or later (choose another with --php=)' => '%s n’est pas PHP 7.4 ou plus récent (choisissez-en un autre avec --php=)',
    '%s has no %s extension' => '%s n’a pas l’extension %s',
    'note: %s has no posix extension (php-process / php-posix); getent is used instead.' => 'note : %s n’a pas l’extension posix (php-process / php-posix); getent est utilisé à la place.',
    'Installing wp-secmon %s (PHP: %s)' => 'Installation de wp-secmon %s (PHP : %s)',
    'cannot write %s' => 'impossible d’écrire %s',
    'kept %s (current defaults in %s)' => '%s conservé (valeurs par défaut actuelles dans %s)',
    'created %s' => '%s créé',
    'note: systemd not detected; schedule "%s <check>" with cron instead' => 'note : systemd non détecté; planifiez « %s <vérification> » avec cron à la place',
    'timers enabled: %s' => 'timers activés : %s',
    'timers installed, not enabled' => 'timers installés, non activés',
    'timers updated, still enabled or disabled as before' => 'timers mis à jour, toujours activés ou désactivés comme avant',
    'WP-CLI: %s (downloaded)' => 'WP-CLI : %s (téléchargé)',
    'note: WP-CLI not installed (%s); install it at %s or set wp_cli in %s'
        => 'note : WP-CLI non installé (%s); installez-le à %s ou réglez wp_cli dans %s',
    'Next steps:' => 'Étapes suivantes :',
    'Review %s (scan_paths, alert_email, language...)' => 'Relisez %s (scan_paths, alert_email, language...)',
    '(records the baselines and prints the first report)' => '(enregistre les états de référence et affiche le premier rapport)',
    'wp-secmon removed. Kept %s, %s and %s (--purge deletes them).' => 'wp-secmon retiré. %s, %s et %s sont conservés (--purge les supprime).',
    'left %s in place (not a wp-secmon directory name)' => '%s laissé en place (pas un nom de dossier wp-secmon)',
    'wp-secmon removed, including configuration, state and logs.' => 'wp-secmon retiré, y compris la configuration, l’état et les journaux.',
    'cannot download %s' => 'impossible de télécharger %s',
    'checksum mismatch for %s' => 'la somme de contrôle de %s ne correspond pas',

    // update
    'cannot read the latest release from %s' => 'impossible de lire la dernière version sur %s',
    'wp-secmon %s is available (this is %s): run wp-secmon update' => 'wp-secmon %s est disponible (celle-ci est %s) : lancez wp-secmon update',
    'wp-secmon %s is up to date' => 'wp-secmon %s est à jour',
    'run the update as root' => 'lancez la mise à jour en tant que root',
    'wp-secmon is not installed: download wp-secmon.phar and run php wp-secmon.phar install'
        => 'wp-secmon n’est pas installé : téléchargez wp-secmon.phar et lancez php wp-secmon.phar install',
    'the installer of wp-secmon %s failed' => 'l’installation de wp-secmon %s a échoué',
    'wp-secmon updated from %s to %s.' => 'wp-secmon mis à jour de %s à %s.',
];
