<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AuditIntegrityService
{
    public function __construct(private Database $db) {}

    public function verify(): array
    {
        $rows = $this->db->all('SELECT * FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id');
        $checkpoint=$this->db->one('SELECT * FROM audit_retention_checkpoints ORDER BY id DESC LIMIT 1');
        $expectedPrevious=$checkpoint['chain_head_hash']??null;
        $verifiedFromCheckpoint=$checkpoint!==null;
        foreach ($rows as $row) {
            if (($row['previous_hash'] ?: null) !== $expectedPrevious) return ['valid'=>false,'broken_at'=>(int)$row['id'],'reason'=>'previous_hash_mismatch','checkpoint'=>$checkpoint['id']??null];
            $payload = json_encode([
                (string)$row['action'],(string)$row['result'],$row['actor_user_id']===null?null:(int)$row['actor_user_id'],$row['subject_user_id']===null?null:(int)$row['subject_user_id'],$row['application_id']===null?null:(int)$row['application_id'],$row['organization_id']===null?null:(int)$row['organization_id'],$row['reason'],(string)($row['ip_address']??''),(string)($row['user_agent']??''),$row['metadata_json'],$row['created_at'],$expectedPrevious
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $hash = hash('sha256', $payload);
            if (!hash_equals((string)$row['entry_hash'], $hash)) return ['valid'=>false,'broken_at'=>(int)$row['id'],'reason'=>'entry_hash_mismatch','checkpoint'=>$checkpoint['id']??null];
            $expectedPrevious = (string)$row['entry_hash'];
        }
        return ['valid'=>true,'entries'=>count($rows),'head'=>$expectedPrevious,'retention_checkpoint'=>$verifiedFromCheckpoint? (int)$checkpoint['id'] : null,'deleted_entries'=>$checkpoint?(int)$checkpoint['deleted_count']:0];
    }
}
