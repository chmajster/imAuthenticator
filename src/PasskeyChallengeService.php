<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class PasskeyChallengeService
{
    public function __construct(private Database $db, private array $config, private AuditLog $audit) {}

    public function registrationOptions(int $userId): array
    {
        $user = $this->db->one('SELECT id,uuid,name,email FROM users WHERE id=? AND enabled=1 AND lifecycle_status=\'active\'', [$userId]);
        if (!$user) throw new RuntimeException('user_not_available');
        $issuer = parse_url((string)$this->config['issuer']);
        $rpId = is_array($issuer) ? (string)($issuer['host'] ?? '') : '';
        if ($rpId === '') throw new RuntimeException('invalid_relying_party');
        $challenge = $this->b64u(random_bytes(32));
        $userHandle = $this->b64u((string)$user['uuid']);
        $this->db->execute('INSERT INTO authentication_challenges(user_id,challenge_hash,purpose,context_json,expires_at) VALUES(?,?,\'webauthn_register\',?,DATE_ADD(NOW(),INTERVAL 5 MINUTE))', [$userId,Security::tokenHash($challenge),json_encode(['challenge'=>$challenge,'rp_id'=>$rpId,'user_handle'=>$userHandle],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)]);
        $exclude = [];
        foreach ($this->db->all('SELECT credential_id FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL', [$userId]) as $row) $exclude[] = ['type'=>'public-key','id'=>$this->b64u((string)$row['credential_id'])];
        return [
            'challenge'=>$challenge,
            'rp'=>['id'=>$rpId,'name'=>'imAuthenticator'],
            'user'=>['id'=>$userHandle,'name'=>$user['email'],'displayName'=>$user['name']],
            'pubKeyCredParams'=>[['type'=>'public-key','alg'=>-7],['type'=>'public-key','alg'=>-257]],
            'timeout'=>60000,
            'attestation'=>'none',
            'authenticatorSelection'=>['residentKey'=>'preferred','userVerification'=>'required'],
            'excludeCredentials'=>$exclude,
        ];
    }

    public function credentials(int $userId): array
    {
        return $this->db->all('SELECT id,name,aaguid,transports_json,backup_eligible,backup_state,created_at,last_used_at FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC', [$userId]);
    }

    public function revoke(int $credentialId, int $userId): void
    {
        $this->db->execute('UPDATE webauthn_credentials SET revoked_at=NOW() WHERE id=? AND user_id=?', [$credentialId,$userId]);
        $this->audit->write('webauthn.credential.revoked','success',$userId,$userId,null,null,['credential_id'=>$credentialId]);
    }

    public function libraryAvailable(): bool { return class_exists('Webauthn\\PublicKeyCredential'); }

    private function b64u(string $value): string { return rtrim(strtr(base64_encode($value),'+/','-_'),'='); }
}
