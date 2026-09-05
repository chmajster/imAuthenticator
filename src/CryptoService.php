<?php
declare(strict_types=1);
namespace ImAuthenticator;
final class CryptoService
{
    private string $key;
    public function __construct(array $config)
    {
        $material=(string)($config['app_key']??'');
        if($material===''){
            $path=dirname(__DIR__).'/config/app.key';
            if(is_file($path))$material=trim((string)file_get_contents($path));
            else{
                $material=rtrim(strtr(base64_encode(random_bytes(32)),'+/','-_'),'=');
                if(!is_dir(dirname($path))&&!mkdir(dirname($path),0750,true)&&!is_dir(dirname($path)))throw new \RuntimeException('cannot_create_config_directory');
                if(file_put_contents($path,$material."\n",LOCK_EX)===false)throw new \RuntimeException('cannot_create_app_key');
                @chmod($path,0600);
            }
        }
        $decoded=base64_decode(strtr($material,'-_','+/'),true);
        $this->key=hash('sha256',is_string($decoded)&&$decoded!==''?$decoded:$material,true);
    }
    public function available():bool{return strlen($this->key)===32;}
    public function encrypt(string $plain):string{if(!$this->available())throw new \RuntimeException('app_key_missing');$iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($plain,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,'imauthenticator');if($cipher===false)throw new \RuntimeException('encryption_failed');return rtrim(strtr(base64_encode($iv.$tag.$cipher),'+/','-_'),'=');}
    public function decrypt(string $encoded):string{if(!$this->available())throw new \RuntimeException('app_key_missing');$p=strtr($encoded,'-_','+/');$p.=str_repeat('=',(4-strlen($p)%4)%4);$raw=base64_decode($p,true);if(!is_string($raw)||strlen($raw)<29)throw new \RuntimeException('invalid_ciphertext');$iv=substr($raw,0,12);$tag=substr($raw,12,16);$cipher=substr($raw,28);$plain=openssl_decrypt($cipher,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,'imauthenticator');if($plain===false)throw new \RuntimeException('decryption_failed');return $plain;}
}
