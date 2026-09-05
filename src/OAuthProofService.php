<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class OAuthProofService
{
    public function __construct(private Database $db, private JwtService $jwt, private AuditLog $audit) {}

    public function policy(array|int $app): array
    {
        $id=is_array($app)?(int)$app['id']:$app;
        return $this->db->one('SELECT * FROM application_oauth_security WHERE application_id=?',[$id]) ?? [
            'application_id'=>$id,'require_par'=>0,'require_pkce'=>0,'require_dpop'=>0,'require_mtls'=>0,'jar_required'=>0,'jarm_enabled'=>0,'token_exchange_enabled'=>0,
        ];
    }

    public function applicationFromClientRequest(array $input, ?string $authorizationHeader): ?array
    {
        $clientId=(string)($input['client_id']??'');
        if($authorizationHeader&&str_starts_with($authorizationHeader,'Basic ')){
            $decoded=base64_decode(substr($authorizationHeader,6),true);
            if(is_string($decoded)&&str_contains($decoded,':'))[$clientId]=explode(':',$decoded,2);
            $clientId=rawurldecode($clientId);
        }
        if($clientId==='')return null;
        return $this->db->one('SELECT * FROM applications WHERE client_id=? AND enabled=1 AND deleted_at IS NULL',[$clientId]);
    }

    public function validateTokenProofs(array $app, array $input, ?string $authorizationHeader, ?string $dpopHeader, ?string $clientCertificatePem): ?string
    {
        $policy=$this->policy($app);
        if((bool)$policy['require_mtls'])$this->validateMtls($app,$clientCertificatePem);
        if(!(bool)$policy['require_dpop'])return null;
        if(!$dpopHeader)throw new \RuntimeException('invalid_dpop_proof');
        return $this->validateDpop($app,$dpopHeader,'POST',$this->jwt->issuer().'/oauth/token',null);
    }

    public function bindIssuedTokens(array $tokens, ?string $jkt): array
    {
        if(!$jkt)return $tokens;
        if(!empty($tokens['access_token']))$this->db->execute('UPDATE oauth_access_tokens SET dpop_jkt=? WHERE token_hash=?',[$jkt,Security::tokenHash((string)$tokens['access_token'])]);
        if(!empty($tokens['refresh_token']))$this->db->execute('UPDATE oauth_refresh_tokens SET dpop_jkt=? WHERE token_hash=?',[$jkt,Security::tokenHash((string)$tokens['refresh_token'])]);
        if(isset($tokens['token_type']))$tokens['token_type']='DPoP';
        return $tokens;
    }

    public function validateResourceProof(string $accessToken, ?string $dpopHeader, string $method, string $absoluteUrl): void
    {
        $row=$this->db->one('SELECT t.id,t.application_id,t.dpop_jkt FROM oauth_access_tokens t WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>NOW()',[Security::tokenHash($accessToken)]);
        if(!$row)throw new \RuntimeException('invalid_token');
        if(!$row['dpop_jkt'])return;
        if(!$dpopHeader)throw new \RuntimeException('invalid_dpop_proof');
        $app=$this->db->one('SELECT * FROM applications WHERE id=?',[(int)$row['application_id']]);if(!$app)throw new \RuntimeException('invalid_token');
        $jkt=$this->validateDpop($app,$dpopHeader,strtoupper($method),$absoluteUrl,$accessToken);
        if(!hash_equals((string)$row['dpop_jkt'],$jkt))throw new \RuntimeException('invalid_dpop_proof');
    }

    public function validateJar(array $app, string $requestJwt): array
    {
        $policy=$this->policy($app);
        if(!(bool)$policy['jar_required']&&$requestJwt==='')return [];
        if($requestJwt==='')throw new \RuntimeException('request_object_required');
        $jwksRow=$this->db->one('SELECT jwks_json FROM application_client_jwks WHERE application_id=?',[(int)$app['id']]);
        if(!$jwksRow)throw new \RuntimeException('client_jwks_missing');
        $jwks=json_decode((string)$jwksRow['jwks_json'],true);if(!is_array($jwks))throw new \RuntimeException('client_jwks_invalid');
        [$header,$claims,$signed,$signature]=$this->decodeJwt($requestJwt);
        $jwk=$this->selectJwk($jwks,$header);
        $this->verifyJws($header,$jwk,$signed,$signature);
        $now=time();
        $aud=$claims['aud']??null;
        if(!in_array((string)($claims['iss']??''),[(string)$app['client_id']],true))throw new \RuntimeException('invalid_request_object');
        if(!$this->audienceMatches($aud,$this->jwt->issuer()))throw new \RuntimeException('invalid_request_object');
        if((int)($claims['exp']??0)<=$now-30||(int)($claims['iat']??$now)>$now+60)throw new \RuntimeException('invalid_request_object');
        if(($claims['client_id']??$app['client_id'])!==$app['client_id'])throw new \RuntimeException('invalid_request_object');
        return $claims;
    }

    public function jarm(array $app, array $responseClaims): string
    {
        $now=time();
        return $this->jwt->sign(array_merge(['iss'=>$this->jwt->issuer(),'aud'=>$app['client_id'],'iat'=>$now,'exp'=>$now+120],$responseClaims));
    }

    private function validateMtls(array $app, ?string $pem): void
    {
        if(!$pem)throw new \RuntimeException('invalid_client');
        $raw=preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/','',$pem);
        $der=is_string($raw)?base64_decode($raw,true):false;if(!is_string($der))throw new \RuntimeException('invalid_client');
        $thumb=hash('sha256',$der);
        $match=$this->db->one('SELECT 1 FROM application_mtls_certificates WHERE application_id=? AND thumbprint_sha256=? AND revoked_at IS NULL AND (valid_from IS NULL OR valid_from<=NOW()) AND (valid_until IS NULL OR valid_until>NOW())',[(int)$app['id'],$thumb]);
        if(!$match){$this->audit->write('oauth.mtls.denied','denied',null,null,(int)$app['id'],'certificate thumbprint not allowlisted');throw new \RuntimeException('invalid_client');}
    }

    private function validateDpop(array $app,string $proof,string $method,string $url,?string $accessToken): string
    {
        [$header,$claims,$signed,$signature]=$this->decodeJwt($proof);
        if(strtolower((string)($header['typ']??''))!=='dpop+jwt'||!isset($header['jwk'])||!is_array($header['jwk']))throw new \RuntimeException('invalid_dpop_proof');
        $this->verifyJws($header,$header['jwk'],$signed,$signature);
        $now=time();$iat=(int)($claims['iat']??0);$jti=(string)($claims['jti']??'');
        if($jti===''||abs($now-$iat)>300||strtoupper((string)($claims['htm']??''))!==strtoupper($method)||!hash_equals($url,(string)($claims['htu']??'')))throw new \RuntimeException('invalid_dpop_proof');
        if($accessToken!==null){$ath=rtrim(strtr(base64_encode(hash('sha256',$accessToken,true)),'+/','-_'),'=');if(!hash_equals($ath,(string)($claims['ath']??'')))throw new \RuntimeException('invalid_dpop_proof');}
        $jtiHash=Security::tokenHash((int)$app['id'].'|'.$jti);if($this->db->one('SELECT 1 FROM oauth_dpop_replay WHERE jti_hash=?',[$jtiHash]))throw new \RuntimeException('invalid_dpop_proof');
        $this->db->execute('INSERT INTO oauth_dpop_replay(jti_hash,application_id,expires_at) VALUES(?,?,DATE_ADD(NOW(),INTERVAL 10 MINUTE))',[$jtiHash,(int)$app['id']]);
        return $this->jwkThumbprint($header['jwk']);
    }

    private function decodeJwt(string $jwt): array
    {
        $parts=explode('.',$jwt);if(count($parts)!==3)throw new \RuntimeException('invalid_jwt');
        $header=json_decode($this->b64d($parts[0]),true);$claims=json_decode($this->b64d($parts[1]),true);$signature=$this->b64d($parts[2]);
        if(!is_array($header)||!is_array($claims)||$signature==='')throw new \RuntimeException('invalid_jwt');
        return [$header,$claims,$parts[0].'.'.$parts[1],$signature];
    }

    private function verifyJws(array $header,array $jwk,string $signed,string $signature): void
    {
        $alg=(string)($header['alg']??'');
        if($alg==='RS256'){$pem=$this->rsaPem($jwk);$ok=openssl_verify($signed,$signature,$pem,OPENSSL_ALGO_SHA256)===1;}
        elseif($alg==='ES256'){$pem=$this->ecPem($jwk);$ok=openssl_verify($signed,$this->ecdsaRawToDer($signature),$pem,OPENSSL_ALGO_SHA256)===1;}
        else throw new \RuntimeException('unsupported_jws_algorithm');
        if(!$ok)throw new \RuntimeException('invalid_jwt_signature');
    }

    private function selectJwk(array $jwks,array $header): array
    {
        $kid=$header['kid']??null;foreach(($jwks['keys']??[]) as $jwk)if(is_array($jwk)&&($kid===null||($jwk['kid']??null)===$kid))return $jwk;throw new \RuntimeException('jwk_not_found');
    }

    private function jwkThumbprint(array $jwk): string
    {
        if(($jwk['kty']??'')==='RSA')$normalized=['e'=>(string)($jwk['e']??''),'kty'=>'RSA','n'=>(string)($jwk['n']??'')];
        elseif(($jwk['kty']??'')==='EC')$normalized=['crv'=>(string)($jwk['crv']??''),'kty'=>'EC','x'=>(string)($jwk['x']??''),'y'=>(string)($jwk['y']??'')];
        else throw new \RuntimeException('unsupported_jwk');
        return rtrim(strtr(base64_encode(hash('sha256',json_encode($normalized,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),true)),'+/','-_'),'=');
    }

    private function rsaPem(array $jwk): string
    {
        if(($jwk['kty']??'')!=='RSA')throw new \RuntimeException('invalid_jwk');$n=$this->b64d((string)($jwk['n']??''));$e=$this->b64d((string)($jwk['e']??''));if($n===''||$e==='')throw new \RuntimeException('invalid_jwk');
        $seq=$this->asnInt($n).$this->asnInt($e);$rsa="\x30".$this->asnLen(strlen($seq)).$seq;$alg="\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";$bit="\x03".$this->asnLen(strlen($rsa)+1)."\0".$rsa;$spki="\x30".$this->asnLen(strlen($alg.$bit)).$alg.$bit;return $this->pem($spki,'PUBLIC KEY');
    }

    private function ecPem(array $jwk): string
    {
        if(($jwk['kty']??'')!=='EC'||($jwk['crv']??'')!=='P-256')throw new \RuntimeException('invalid_jwk');$x=$this->b64d((string)($jwk['x']??''));$y=$this->b64d((string)($jwk['y']??''));if(strlen($x)!==32||strlen($y)!==32)throw new \RuntimeException('invalid_jwk');$point="\x04".$x.$y;$alg="\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";$bit="\x03".$this->asnLen(strlen($point)+1)."\0".$point;$spki="\x30".$this->asnLen(strlen($alg.$bit)).$alg.$bit;return $this->pem($spki,'PUBLIC KEY');
    }

    private function ecdsaRawToDer(string $raw): string
    {
        if(strlen($raw)!==64)throw new \RuntimeException('invalid_ecdsa_signature');$r=substr($raw,0,32);$s=substr($raw,32);$seq=$this->asnInt($r).$this->asnInt($s);return "\x30".$this->asnLen(strlen($seq)).$seq;
    }
    private function asnInt(string $v):string{$v=ltrim($v,"\0");if($v==='' )$v="\0";if((ord($v[0])&0x80)!==0)$v="\0".$v;return"\x02".$this->asnLen(strlen($v)).$v;}
    private function asnLen(int $l):string{if($l<128)return chr($l);$b=ltrim(pack('N',$l),"\0");return chr(0x80|strlen($b)).$b;}
    private function pem(string $der,string $label):string{return"-----BEGIN {$label}-----\n".chunk_split(base64_encode($der),64,"\n")."-----END {$label}-----\n";}
    private function b64d(string $v):string{$p=strtr($v,'-_','+/');$p.=str_repeat('=',(4-strlen($p)%4)%4);$r=base64_decode($p,true);return is_string($r)?$r:'';}
    private function audienceMatches(mixed $aud,string $expected):bool{return is_string($aud)?hash_equals($expected,$aud):(is_array($aud)&&in_array($expected,$aud,true));}
}
