<?php
declare(strict_types=1);
namespace ImAuthenticator;
final class CryptoService
{
    private string $key;
    public function __construct(array $config){$material=(string)($config['app_key']??'');if($material==='')$this->key='';else{$decoded=base64_decode(strtr($material,'-_','+/'),true);$this->key=hash('sha256',is_string($decoded)&&$decoded!==''?$decoded:$material,true);}}
    public function available():bool{return $this->key!=='';}
    public function encrypt(string $plain):string{if(!$this->available())throw new \RuntimeException('app_key_missing');$iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($plain,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,'imauthenticator');if($cipher===false)throw new \RuntimeException('encryption_failed');return rtrim(strtr(base64_encode($iv.$tag.$cipher),'+/','-_'),'=');}
    public function decrypt(string $encoded):string{if(!$this->available())throw new \RuntimeException('app_key_missing');$raw=base64_decode(strtr($encoded,'-_','+/'),true);if(!is_string($raw)||strlen($raw)<29)throw new \RuntimeException('invalid_ciphertext');$iv=substr($raw,0,12);$tag=substr($raw,12,16);$cipher=substr($raw,28);$plain=openssl_decrypt($cipher,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,'imauthenticator');if($plain===false)throw new \RuntimeException('decryption_failed');return $plain;}
}
