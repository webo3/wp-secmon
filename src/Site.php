<?php

declare(strict_types=1);

namespace WpSecMon;

final class Site
{
    /** Stable id: first 12 hex digits of sha256(root). */
    public string $id;
    /** WordPress root (directory holding wp-load.php and wp-includes/). */
    public string $root;
    /** wp-config.php, in the root or its parent. */
    public string $config;
    /** Account the site is checked as (never root). */
    public string $user;

    public function __construct(string $root, string $config, string $user)
    {
        $this->id = self::idFor($root);
        $this->root = $root;
        $this->config = $config;
        $this->user = $user;
    }

    public static function idFor(string $root): string
    {
        return substr(hash('sha256', $root), 0, 12);
    }

    public function toArray(): array
    {
        return ['id' => $this->id, 'root' => $this->root, 'config' => $this->config, 'user' => $this->user];
    }

    public static function fromArray(array $a): self
    {
        return new self((string) $a['root'], (string) $a['config'], (string) $a['user']);
    }
}
