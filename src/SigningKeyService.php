<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class SigningKeyService
{
    public function __construct(private Database $db,private AuditLog $audit,private array $config,private string $configFile) {}

    public function rotate(int $actorUserId,int $graceSeconds=7200): array
    {
        $graceSeconds=max(3600,min(604800,$graceSeconds));
        $keyDir=dirname((string)($this->config['keys']['private']??$this->configFile));
        if(!is_dir($keyDir)&&!mkdir($keyDir,0700,true)&&!is_dir($keyDir))throw new RuntimeException('cannot_create_key_directory');
        $key=openssl_pkey_new(['private_key_bits'=>3072,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);if($key===false)throw new RuntimeException('key_generation_failed');
        if(!openssl_pkey_export($key,$privatePem))throw new RuntimeException('private_key_export_failed');$details=openssl_pkey_get_details($key);if(!is_array($details)||empty($details['key']))throw new RuntimeException('public_key_export_failed');$publicPem=(string)$details['key'];
        $kid=substr(hash('sha256',$publicPem),0,24);$privatePath=$keyDir.'/private-'.$kid.'.pem';$publicPath=$keyDir.'/public-'.$kid.'.pem';
        if(file_put_contents($privatePath,$privatePem,LOCK_EX)===false||file_put_contents($publicPath,$publicPem,LOCK_EX)===false)throw new RuntimeException('key_write_failed');@chmod($privatePath,0600);@chmod($publicPath,0644);

        $oldKid=(string)($this->config['keys']['kid']??'');$oldPrivate=(string)($this->config['keys']['private']??'');$oldPublicPath=(string)($this->config['keys']['public']??'');$oldPublic=$oldPublicPath!==''?@file_get_contents($oldPublicPath):false;$notAfter=date('Y-m-d H:i:s',time()+$graceSeconds);
        $this->db->transaction(function()use($oldKid,$oldPrivate,$oldPublic,$notAfter,$kid,$privatePath,$publicPem):void{
            if($oldKid!==''&&is_string($oldPublic)&&$oldPublic!==''){
                $this->db->execute("INSERT INTO signing_keys(kid,algorithm,public_key_pem,private_key_ref,storage_provider,status,not_before,not_after) VALUES(?,'RS256',?,?,'file','retiring',NOW(),?) ON DUPLICATE KEY UPDATE public_key_pem=VALUES(public_key_pem),private_key_ref=VALUES(private_key_ref),status='retiring',not_after=VALUES(not_after)",[$oldKid,$oldPublic,$oldPrivate,$notAfter]);
            }
            $this->db->execute("UPDATE signing_keys SET status='retiring',not_after=COALESCE(not_after,?) WHERE status='active' AND kid<>?",[$notAfter,$kid]);
            $this->db->execute("INSERT INTO signing_keys(kid,algorithm,public_key_pem,private_key_ref,storage_provider,status,not_before) VALUES(?,'RS256',?,?,'file','active',NOW()) ON DUPLICATE KEY UPDATE public_key_pem=VALUES(public_key_pem),private_key_ref=VALUES(private_key_ref),status='active',not_after=NULL",[$kid,$publicPem,$privatePath]);
        });
        $newConfig=$this->config;$newConfig['keys']=['private'=>$privatePath,'public'=>$publicPath,'kid'=>$kid];$tmp=$this->configFile.'.tmp.'.bin2hex(random_bytes(4));$payload="<?php\nreturn ".var_export($newConfig,true).";\n";if(file_put_contents($tmp,$payload,LOCK_EX)===false){@unlink($tmp);throw new RuntimeException('config_write_failed');}@chmod($tmp,0640);if(!@rename($tmp,$this->configFile)){@unlink($tmp);throw new RuntimeException('config_replace_failed');}
        $this->audit->write('signing_key.rotated','success',$actorUserId,null,null,null,['kid'=>$kid,'previous_kid'=>$oldKid,'grace_seconds'=>$graceSeconds]);
        return ['kid'=>$kid,'previous_kid'=>$oldKid,'old_key_visible_until'=>$notAfter];
    }

    public function jwks(): array
    {
        $keys=[];$seen=[];
        $currentKid=(string)($this->config['keys']['kid']??'');$currentPublicPath=(string)($this->config['keys']['public']??'');$currentPublic=$currentPublicPath!==''?@file_get_contents($currentPublicPath):false;
        if($currentKid!==''&&is_string($currentPublic)&&$currentPublic!==''){$jwk=$this->pemToJwk($currentPublic,$currentKid);if($jwk){$keys[]=$jwk;$seen[$currentKid]=true;}}
        $rows=$this->db->all("SELECT kid,public_key_pem FROM signing_keys WHERE status IN ('active','retiring') AND (not_after IS NULL OR not_after>NOW()) ORDER BY created_at DESC");
        foreach($rows as $row){$kid=(string)$row['kid'];if(isset($seen[$kid]))continue;$jwk=$this->pemToJwk((string)$row['public_key_pem'],$kid);if($jwk){$keys[]=$jwk;$seen[$kid]=true;}}
        return ['keys'=>$keys];
    }

    public function retireExpired(): int
    {
        return $this->db->execute("UPDATE signing_keys SET status='retired',retired_at=COALESCE(retired_at,NOW()) WHERE status='retiring' AND not_after IS NOT NULL AND not_after<=NOW()");
    }

    private function pemToJwk(string $pem,string $kid): ?array
    {
        $key=openssl_pkey_get_public($pem);$details=$key?openssl_pkey_get_details($key):false;if(!is_array($details)||empty($details['rsa']))return null;$b64=static fn(string $v):string=>rtrim(strtr(base64_encode($v),'+/','-_'),'=');return ['kty'=>'RSA','use'=>'sig','alg'=>'RS256','kid'=>$kid,'n'=>$b64($details['rsa']['n']),'e'=>$b64($details['rsa']['e'])];
    }
}
