<?php

declare(strict_types=1);

namespace App\Database;

use App\Config\AppConfig;
use App\Security\Crypto;

final class Connection
{
    private static ?\PDO $pdo = null;

    public static function get(): \PDO
    {
        if (self::$pdo instanceof \PDO) {
            return self::$pdo;
        }

        $secretKeyPath = AppConfig::secretKeyPath();
        if (!is_file($secretKeyPath)) {
            throw new \RuntimeException('Brak klucza aplikacji. Ustaw podczas pierwszego logowania.');
        }
        $key = file_get_contents($secretKeyPath);
        if ($key === false) {
            throw new \RuntimeException('Nie można odczytać klucza aplikacji');
        }

        $encPath = AppConfig::mssqlConfigPath();
        if (!is_file($encPath)) {
            throw new \RuntimeException('Brak skonfigurowanego połączenia do MSSQL.');
        }
        $json = json_decode((string)file_get_contents($encPath), true, 512, JSON_THROW_ON_ERROR);
        $host = Crypto::decrypt($json['data'], $json['iv'], $json['tag'], $key);
        $username = Crypto::decrypt($json['user']['data'], $json['user']['iv'], $json['user']['tag'], $key);
        $password = Crypto::decrypt($json['pass']['data'], $json['pass']['iv'], $json['pass']['tag'], $key);
        $database = Crypto::decrypt($json['db']['data'], $json['db']['iv'], $json['db']['tag'], $key);

        $dsn = "sqlsrv:Server={$host};Database={$database}";
        $pdo = new \PDO($dsn, $username, $password, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);

        self::$pdo = $pdo;
        return $pdo;
    }
}


