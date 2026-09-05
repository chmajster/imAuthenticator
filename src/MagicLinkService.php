<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class MagicLinkService
{
    public function __construct(private Database $db,private MailQueueService $mail,private AuditLog $audit,private array $config) {}

    public function request(string $identifier,string $returnPath='/dashboard'): void
    {
        $identifier=strtolower(trim($identifier));
        $user=$this->db->one("SELECT DISTINCT u.* FROM users u LEFT JOIN user_emails ue ON ue.user_id=u.id WHERE (LOWER(u.email)=? OR LOWER(u.username)=? OR LOWER(ue.email)=?) AND u.enabled=1 AND u.lifecycle_status='active' LIMIT 1",[$identifier,$identifier,$identifier]);
        if(!$user){$this->audit->write('auth.magic_link.request','success',null,null,null,'non-enumerating request');return;}
        if(!str_starts_with($returnPath,'/')||str_starts_with($returnPath,'//'))$returnPath='/dashboard';
        $token=Security::randomToken(48);$expires=date('Y-m-d H:i:s',time()+900);
        $this->db->execute('INSERT INTO magic_login_tokens(user_id,token_hash,return_path,requested_ip,expires_at) VALUES(?,?,?,?,?)',[(int)$user['id'],Security::tokenHash($token),$returnPath,Security::currentIp(),$expires]);
        $issuer=rtrim((string)$this->config['issuer'],'/');$link=$issuer.'/magic-login/consume?token='.rawurlencode($token);
        $this->mail->queue((string)$user['email'],'Link do logowania imAuthenticator',"Link jest jednorazowy i ważny 15 minut:\n\n{$link}\n\nJeżeli nie prosiłeś o logowanie, zignoruj tę wiadomość.",'magic_link',(int)$user['id']);
        $this->audit->write('auth.magic_link.request','success',(int)$user['id'],(int)$user['id']);
    }

    public function consume(string $token): array
    {
        return $this->db->transaction(function()use($token):array{
            $row=$this->db->one('SELECT m.*,u.enabled,u.lifecycle_status,u.account_starts_at,u.account_ends_at FROM magic_login_tokens m JOIN users u ON u.id=m.user_id WHERE m.token_hash=? FOR UPDATE',[Security::tokenHash($token)]);
            if(!$row||$row['used_at']!==null||strtotime((string)$row['expires_at'])<=time()||!(bool)$row['enabled']||$row['lifecycle_status']!=='active')throw new \RuntimeException('invalid_or_expired_link');
            if($row['account_starts_at']&&strtotime((string)$row['account_starts_at'])>time())throw new \RuntimeException('account_not_active');
            if($row['account_ends_at']&&strtotime((string)$row['account_ends_at'])<=time())throw new \RuntimeException('account_not_active');
            $this->db->execute('UPDATE magic_login_tokens SET used_at=NOW() WHERE id=?',[(int)$row['id']]);
            $this->audit->write('auth.magic_link.success','success',(int)$row['user_id'],(int)$row['user_id']);
            return ['user_id'=>(int)$row['user_id'],'return_path'=>(string)($row['return_path']?:'/dashboard')];
        });
    }
}
