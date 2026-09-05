<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class PasskeyChallengeService
{
    public function __construct(private Database $db, private array $config, private AuditLog $audit) {}

    public function registrationOptions(int $userId): array
    {
        $this->assertLibrary();
        $user = $this->activeUser($userId);
        $rpId = $this->rpId();
        $challengeRaw = random_bytes(32);
        $challenge = $this->b64u($challengeRaw);
        $context = ['challenge'=>$challenge,'rp_id'=>$rpId,'user_handle'=>$this->b64u((string)$user['uuid'])];
        $this->db->execute('INSERT INTO authentication_challenges(user_id,challenge_hash,purpose,context_json,expires_at) VALUES(?,?,\'webauthn_register\',?,DATE_ADD(NOW(),INTERVAL 5 MINUTE))', [$userId,Security::tokenHash($challenge),json_encode($context,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)]);
        $challengeId = $this->db->lastInsertId();
        $exclude = [];
        foreach ($this->db->all('SELECT credential_id,transports_json FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL', [$userId]) as $row) {
            $transports = json_decode((string)($row['transports_json'] ?? '[]'), true);
            $exclude[] = ['type'=>'public-key','id'=>$this->b64u((string)$row['credential_id']),'transports'=>is_array($transports)?$transports:[]];
        }
        return ['challenge_id'=>$challengeId,'publicKey'=>[
            'challenge'=>$challenge,
            'rp'=>['id'=>$rpId,'name'=>'imAuthenticator'],
            'user'=>['id'=>$this->b64u((string)$user['uuid']),'name'=>$user['email'],'displayName'=>$user['name']],
            'pubKeyCredParams'=>[['type'=>'public-key','alg'=>-7],['type'=>'public-key','alg'=>-257]],
            'timeout'=>60000,
            'attestation'=>'none',
            'authenticatorSelection'=>['residentKey'=>'required','requireResidentKey'=>true,'userVerification'=>'required'],
            'excludeCredentials'=>$exclude,
        ]];
    }

    public function completeRegistration(int $userId, int $challengeId, string $credentialJson, ?string $name = null): int
    {
        $this->assertLibrary();
        $user = $this->activeUser($userId);
        $challenge = $this->challenge($challengeId,'webauthn_register',$userId);
        $serializer = $this->serializer();
        $credential = $serializer->deserialize($credentialJson, PublicKeyCredential::class, 'json');
        if (!$credential instanceof PublicKeyCredential || !$credential->response instanceof AuthenticatorAttestationResponse) throw new RuntimeException('invalid_attestation_response');
        $options = $this->creationOptionsObject($user,$this->b64uDecode((string)$challenge['challenge']));
        $factory = $this->ceremonyFactory();
        $record = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())->check($credential->response,$options,$this->rpId());
        if ($record->attestationType !== 'none') throw new RuntimeException('unsupported_attestation_type');
        if ($this->db->one('SELECT 1 FROM webauthn_credentials WHERE credential_id=?',[$record->publicKeyCredentialId])) throw new RuntimeException('credential_already_registered');
        $transports = array_values(array_unique(array_filter(array_map('strval',$record->transports))));
        $aaguid = $record->aaguid->toRfc4122();
        $this->db->transaction(function() use($record,$userId,$name,$transports,$aaguid,$challengeId):void{
            $updated=$this->db->execute('UPDATE authentication_challenges SET used_at=NOW() WHERE id=? AND used_at IS NULL AND expires_at>NOW()',[$challengeId]);if($updated!==1)throw new RuntimeException('challenge_used_or_expired');
            $this->db->execute('INSERT INTO webauthn_credentials(user_id,name,credential_id,public_key_cose,sign_count,aaguid,transports_json,attestation_type,backup_eligible,backup_state,uv_initialized) VALUES(?,?,?,?,?,?,?,?,?,?,?)',[
                $userId,trim((string)$name)?:'Passkey',$record->publicKeyCredentialId,$record->credentialPublicKey,$record->counter,$aaguid,json_encode($transports,JSON_THROW_ON_ERROR),$record->attestationType,(int)($record->backupEligible??false),(int)($record->backupStatus??false),(int)($record->uvInitialized??true)
            ]);
        });
        $id=$this->db->lastInsertId();
        $this->audit->write('webauthn.credential.registered','success',$userId,$userId,null,null,['credential_id'=>$id,'aaguid'=>$aaguid,'transports'=>$transports]);
        return $id;
    }

    public function authenticationOptions(): array
    {
        $this->assertLibrary();
        $rpId=$this->rpId();$challengeRaw=random_bytes(32);$challenge=$this->b64u($challengeRaw);
        $this->db->execute('INSERT INTO authentication_challenges(user_id,challenge_hash,purpose,context_json,expires_at) VALUES(NULL,?,\'webauthn_login\',?,DATE_ADD(NOW(),INTERVAL 5 MINUTE))',[Security::tokenHash($challenge),json_encode(['challenge'=>$challenge,'rp_id'=>$rpId],JSON_THROW_ON_ERROR)]);
        return ['challenge_id'=>$this->db->lastInsertId(),'publicKey'=>['challenge'=>$challenge,'rpId'=>$rpId,'allowCredentials'=>[],'userVerification'=>'required','timeout'=>60000]];
    }

    public function completeAuthentication(int $challengeId, string $credentialJson): int
    {
        $this->assertLibrary();
        $challenge=$this->challenge($challengeId,'webauthn_login',null);
        $credential=$this->serializer()->deserialize($credentialJson,PublicKeyCredential::class,'json');
        if(!$credential instanceof PublicKeyCredential||!$credential->response instanceof AuthenticatorAssertionResponse)throw new RuntimeException('invalid_assertion_response');
        $row=$this->db->one('SELECT wc.*,u.uuid,u.enabled,u.lifecycle_status,u.account_starts_at,u.account_ends_at FROM webauthn_credentials wc JOIN users u ON u.id=wc.user_id WHERE wc.credential_id=? AND wc.revoked_at IS NULL',[$credential->rawId]);
        if(!$row||!$this->userRowActive($row))throw new RuntimeException('credential_not_available');
        if(empty($row['aaguid']))throw new RuntimeException('legacy_credential_not_supported');
        $record=CredentialRecord::create(
            (string)$row['credential_id'],PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,$this->decodeArray($row['transports_json']),
            (string)($row['attestation_type']?:'none'),EmptyTrustPath::create(),Uuid::fromString((string)$row['aaguid']),(string)$row['public_key_cose'],(string)$row['uuid'],(int)$row['sign_count'],null,(bool)$row['backup_eligible'],(bool)$row['backup_state'],(bool)$row['uv_initialized']
        );
        $options=PublicKeyCredentialRequestOptions::create($this->b64uDecode((string)$challenge['challenge']),$this->rpId(),[],PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,60000);
        $validated=AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory()->requestCeremony())->check($record,$credential->response,$options,$this->rpId(),null);
        $this->db->transaction(function()use($challengeId,$row,$validated):void{
            $updated=$this->db->execute('UPDATE authentication_challenges SET used_at=NOW() WHERE id=? AND used_at IS NULL AND expires_at>NOW()',[$challengeId]);if($updated!==1)throw new RuntimeException('challenge_used_or_expired');
            $this->db->execute('UPDATE webauthn_credentials SET sign_count=?,backup_eligible=?,backup_state=?,uv_initialized=?,last_used_at=NOW() WHERE id=?',[$validated->counter,(int)($validated->backupEligible??false),(int)($validated->backupStatus??false),(int)($validated->uvInitialized??true),(int)$row['id']]);
        });
        $userId=(int)$row['user_id'];$this->audit->write('webauthn.login.success','success',$userId,$userId,null,null,['credential_id'=>(int)$row['id']]);return $userId;
    }

    public function credentials(int $userId): array
    {
        return $this->db->all('SELECT id,name,aaguid,transports_json,backup_eligible,backup_state,created_at,last_used_at FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC', [$userId]);
    }

    public function revoke(int $credentialId, int $userId): void
    {
        $changed=$this->db->execute('UPDATE webauthn_credentials SET revoked_at=NOW() WHERE id=? AND user_id=? AND revoked_at IS NULL', [$credentialId,$userId]);
        if($changed>0)$this->audit->write('webauthn.credential.revoked','success',$userId,$userId,null,null,['credential_id'=>$credentialId]);
    }

    public function libraryAvailable(): bool { return class_exists(PublicKeyCredential::class) && class_exists(WebauthnSerializerFactory::class); }

    private function creationOptionsObject(array $user,string $challengeRaw): PublicKeyCredentialCreationOptions
    {
        $exclude=[];foreach($this->db->all('SELECT credential_id,transports_json FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL',[(int)$user['id']]) as $row)$exclude[]=PublicKeyCredentialDescriptor::create('public-key',(string)$row['credential_id'],$this->decodeArray($row['transports_json']));
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('imAuthenticator',$this->rpId()),PublicKeyCredentialUserEntity::create((string)$user['email'],(string)$user['uuid'],(string)$user['name']),$challengeRaw,
            [PublicKeyCredentialParameters::createPk(-7),PublicKeyCredentialParameters::createPk(-257)],AuthenticatorSelectionCriteria::create(null,AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED),PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,$exclude,60000
        );
    }

    private function serializer(): object
    {
        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    private function ceremonyFactory(): CeremonyStepManagerFactory
    {
        $factory=new CeremonyStepManagerFactory();$factory->setAllowedOrigins([$this->origin()]);return $factory;
    }

    private function challenge(int $id,string $purpose,?int $userId): array
    {
        $params=[$id,$purpose];$sql='SELECT * FROM authentication_challenges WHERE id=? AND purpose=? AND used_at IS NULL AND expires_at>NOW()';if($userId!==null){$sql.=' AND user_id=?';$params[]=$userId;}else{$sql.=' AND user_id IS NULL';}$row=$this->db->one($sql,$params);if(!$row)throw new RuntimeException('challenge_used_or_expired');$context=json_decode((string)$row['context_json'],true);if(!is_array($context)||empty($context['challenge']))throw new RuntimeException('invalid_challenge');return $context;
    }

    private function activeUser(int $userId): array
    {
        $user=$this->db->one('SELECT id,uuid,name,email,enabled,lifecycle_status,account_starts_at,account_ends_at FROM users WHERE id=?',[$userId]);if(!$this->userRowActive($user))throw new RuntimeException('user_not_available');return $user;
    }

    private function userRowActive(?array $user): bool
    {
        if(!$user||!(bool)$user['enabled']||($user['lifecycle_status']??'active')!=='active')return false;$now=time();if(!empty($user['account_starts_at'])&&strtotime((string)$user['account_starts_at'])>$now)return false;if(!empty($user['account_ends_at'])&&strtotime((string)$user['account_ends_at'])<=$now)return false;return true;
    }

    private function rpId(): string
    {
        $host=parse_url((string)$this->config['issuer'],PHP_URL_HOST);if(!is_string($host)||$host==='')throw new RuntimeException('invalid_relying_party');return strtolower($host);
    }

    private function origin(): string
    {
        $parts=parse_url((string)$this->config['issuer']);if(!is_array($parts)||empty($parts['scheme'])||empty($parts['host']))throw new RuntimeException('invalid_relying_party');$origin=strtolower((string)$parts['scheme']).'://'.strtolower((string)$parts['host']);if(isset($parts['port']))$origin.=':'.(int)$parts['port'];return $origin;
    }

    private function assertLibrary(): void { if(!$this->libraryAvailable())throw new RuntimeException('webauthn_library_unavailable'); }
    private function decodeArray(mixed $json): array{$v=json_decode((string)($json??'[]'),true);return is_array($v)?array_values(array_map('strval',$v)):[];}
    private function b64u(string $value): string { return rtrim(strtr(base64_encode($value),'+/','-_'),'='); }
    private function b64uDecode(string $value): string { $pad=strlen($value)%4;if($pad)$value.=str_repeat('=',4-$pad);$decoded=base64_decode(strtr($value,'-_','+/'),true);if($decoded===false)throw new RuntimeException('invalid_base64url');return $decoded; }
}
