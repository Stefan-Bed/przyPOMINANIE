<?php

declare(strict_types=1);

namespace App\Config;

final class AppConfig
{
    public static function storagePath(): string
    {
        return dirname(__DIR__, 2) . '/storage';
    }

    public static function secretKeyPath(): string
    {
        return self::storagePath() . '/app.key';
    }

    public static function mssqlConfigPath(): string
    {
        return self::storagePath() . '/mssql.enc.json';
    }
}


