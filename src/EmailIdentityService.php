<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class EmailIdentityService
{
    public function __construct(private Database $db,private MailQueueService $mail,private AuditLog $audit,private array $config) {}

    public function list(int $userId): array{return $this->db->all('SELECT id,email,is_primary,verified_at,created_at FROM user_emails WHERE user_id=? ORDER BY is_primary DESC,id',[$userId]);}

    public function add(int $userId,string $email): void
    {
        $email=strtolower(trim($email));if(!filter_var($email,FILTER_VALIDATE_EMAIL))throw new \RuntimeException('invalid_email');
        $this->db->execute('INSERT INTO user_emails(user_id,email,is_primary) VALUES(?,?,0)',[$userId,$email]);$id=$this->db->lastInsertId();$this->sendVerification($id,$userId);
        $this->audit->write('user.email.added','success',$userId,$userId,null,null,['email'=>$email]);
    }

    public function sendVerification(int $emailId,int $userId): void
    {
        $row=$this->db->one('SELECT * FROM user_emails WHERE id=? AND user_id=?',[$emailId,$userId]);if(!$row)throw new \RuntimeException('email_not_found');if($row['verified_at'])return;
        $token=Security::randomToken(48);$this->db->execute('INSERT INTO email_verification_tokens(user_email_id,token_hash,expires_at) VALUES(?,?,DATE_ADD(NOW(),INTERVAL 30 MINUTE))',[$emailId,Security::tokenHash($token)]);
        $url=rtrim((string)$this->config['issuer'],'/').'/account/emails/verify?token='.rawurlencode($token);$this->mail->queue((string)$row['email'],'Potwierdź adres e-mail',"Potwierdź adres e-mail:\n\n{$url}\n\nLink jest ważny 30 minut.",'email_verification',$userId);
    }

    public function verify(string $token): int
    {
        return $this->db->transaction(function()use($token):int{$row=$this->db->one('SELECT evt.id AS token_id,ue.id AS email_id,ue.user_id FROM email_verification_tokens evt JOIN user_emails ue ON ue.id=evt.user_email_id WHERE evt.token_hash=? AND evt.used_at IS NULL AND evt.expires_at>NOW() FOR UPDATE',[Security::tokenHash($token)]);if(!$row)throw new \RuntimeException('invalid_or_expired_token');$this->db->execute('UPDATE user_emails SET verified_at=NOW() WHERE id=?',[(int)$row['email_id']]);$this->db->execute('UPDATE email_verification_tokens SET used_at=NOW() WHERE id=?',[(int)$row['token_id']]);$this->audit->write('user.email.verified','success',(int)$row['user_id'],(int)$row['user_id']);return (int)$row['user_id'];});
    }

    public function makePrimary(int $emailId,int $userId): void
    {
        $row=$this->db->one('SELECT email,verified_at FROM user_emails WHERE id=? AND user_id=?',[$emailId,$userId]);if(!$row||!$row['verified_at'])throw new \RuntimeException('verified_email_required');
        $this->db->transaction(function()use($emailId,$userId,$row):void{$this->db->execute('UPDATE user_emails SET is_primary=0 WHERE user_id=?',[$userId]);$this->db->execute('UPDATE user_emails SET is_primary=1 WHERE id=?',[$emailId]);$this->db->execute('UPDATE users SET email=? WHERE id=?',[$row['email'],$userId]);});
        $this->audit->write('user.email.primary_changed','success',$userId,$userId,null,null,['email_id'=>$emailId]);
    }

    public function remove(int $emailId,int $userId): void
    {
        $row=$this->db->one('SELECT is_primary FROM user_emails WHERE id=? AND user_id=?',[$emailId,$userId]);if(!$row)throw new \RuntimeException('email_not_found');if((bool)$row['is_primary'])throw new \RuntimeException('cannot_remove_primary_email');$this->db->execute('DELETE FROM user_emails WHERE id=? AND user_id=?',[$emailId,$userId]);$this->audit->write('user.email.removed','success',$userId,$userId,null,null,['email_id'=>$emailId]);
    }
}
