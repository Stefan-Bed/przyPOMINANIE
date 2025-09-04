<?php

declare(strict_types=1);

namespace App\Database;

final class DocumentRepository
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function fetchUnsettledDocuments(): array
    {
        $sql = <<<SQL
            SELECT
                DH.ID_KONTRAHENTA,
                K.NAZWA AS KONTRAHENT_NAZWA,
                DH.NUMER,
                DH.FORMA_PLATNOSCI,
                CONVERT(varchar(10), DATEADD(DAY, TRY_CAST(DH.TERMIN_PLAT AS int) - 4, '18010101'), 23) AS TERMIN_PLAT,
                DATEDIFF(DAY, DATEADD(DAY, TRY_CAST(DH.TERMIN_PLAT AS int) - 4, '18010101'), GETDATE()) AS DNI_PO_TERMINIE,
                COALESCE(DH.POZOSTALO, DH.POZOSTALO_WAL, 0) AS POZOSTALO
            FROM DOKUMENT_HANDLOWY AS DH
            LEFT JOIN KONTRAHENT AS K ON K.ID_KONTRAHENTA = DH.ID_KONTRAHENTA
            WHERE COALESCE(DH.POZOSTALO, DH.POZOSTALO_WAL, 0) > 0
              AND (DH.FORMA_PLATNOSCI IS NULL OR UPPER(DH.FORMA_PLATNOSCI) <> 'KARTA KREDYTOWA')
            ORDER BY K.NAZWA ASC, DATEADD(DAY, TRY_CAST(DH.TERMIN_PLAT AS int) - 4, '18010101') ASC
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll();
    }
}


