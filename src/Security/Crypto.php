<?php

declare(strict_types=1);

namespace App\Security;

final class Crypto
{
    private const CIPHER = 'aes-256-gcm';

    public static function encrypt(string $plaintext, string $key): array
    {
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }
        return [
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'data' => base64_encode($ciphertext),
        ];
    }

    public static function decrypt(string $dataB64, string $ivB64, string $tagB64, string $key): string
    {
        $iv = base64_decode($ivB64, true);
        $tag = base64_decode($tagB64, true);
        $data = base64_decode($dataB64, true);
        if ($iv === false || $tag === false || $data === false) {
            throw new \InvalidArgumentException('Invalid base64 input');
        }
        $plaintext = openssl_decrypt($data, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed');
        }
        return $plaintext;
    }
}


