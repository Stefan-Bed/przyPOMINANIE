<?php

declare(strict_types=1);

use App\Config\AppConfig;
use App\Security\Crypto;

require_once __DIR__ . '/../vendor/autoload.php';

session_start();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$secretKeyPath = AppConfig::secretKeyPath();
$encPath = AppConfig::mssqlConfigPath();

if ($method === 'POST' && isset($_POST['first_setup'])) {
    $key = bin2hex(random_bytes(32));
    if (!is_dir(dirname($secretKeyPath))) {
        mkdir(dirname($secretKeyPath), 0770, true);
    }
    file_put_contents($secretKeyPath, $key);

    $host = trim($_POST['host'] ?? '');
    $user = trim($_POST['user'] ?? '');
    $pass = (string)($_POST['pass'] ?? '');
    $db = trim($_POST['db'] ?? '');

    $hostEnc = Crypto::encrypt($host, $key);
    $userEnc = Crypto::encrypt($user, $key);
    $passEnc = Crypto::encrypt($pass, $key);
    $dbEnc = Crypto::encrypt($db, $key);

    $payload = [
        'data' => $hostEnc['data'], 'iv' => $hostEnc['iv'], 'tag' => $hostEnc['tag'],
        'user' => $userEnc, 'pass' => $passEnc, 'db' => $dbEnc,
    ];
    file_put_contents($encPath, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    header('Location: /przyPOMINANIE/');
    exit;
}

$hasConfig = is_file($secretKeyPath) && is_file($encPath);

?><!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>przyPOMINANIE</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; margin: 2rem; }
        .card { max-width: 640px; padding: 1.25rem; border: 1px solid #ddd; border-radius: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
        label { display:block; margin-top: .75rem; font-weight: 600; }
        input { width: 100%; padding: .5rem .6rem; border:1px solid #ccc; border-radius: 8px; }
        button { margin-top: 1rem; padding: .6rem 1rem; border-radius: 8px; border: 1px solid #0b5; background:#0c6; color:#fff; cursor:pointer; }
        button:hover { background:#0b5; }
        .muted { color:#666; font-size:.9rem; }
    </style>
    <base href="/przyPOMINANIE/" />
</head>
<body>
<div class="card">
<?php if (!$hasConfig): ?>
    <h2>Pierwsze logowanie – konfiguracja MSSQL</h2>
    <p class="muted">Serwer i baza wstępnie uzupełnione: 192.168.0.3 / BUDUJ</p>
    <form method="post">
        <input type="hidden" name="first_setup" value="1" />
        <label>Serwer</label>
        <input name="host" value="192.168.0.3" required />
        <label>Baza danych</label>
        <input name="db" value="BUDUJ" required />
        <label>Login</label>
        <input name="user" placeholder="login do MSSQL" required />
        <label>Hasło</label>
        <input name="pass" type="password" placeholder="hasło do MSSQL" required />
        <button type="submit">Zapisz konfigurację</button>
    </form>
<?php else: ?>
    <h2>przyPOMINANIE</h2>
    <p class="muted">Konfiguracja połączenia zapisana. Wkrótce dodamy logikę pobierania dokumentów.</p>
<?php endif; ?>
</div>
</body>
</html>


