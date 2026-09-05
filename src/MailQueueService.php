<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class MailQueueService
{
    public function __construct(private Database $db, private AuditLog $audit, private array $config) {}

    public function queue(string $recipient, string $subject, string $body, string $type='notification', ?int $userId=null): int
    {
        if (!filter_var($recipient,FILTER_VALIDATE_EMAIL)) throw new \RuntimeException('invalid_recipient');
        $this->db->execute('INSERT INTO email_outbox(user_id,recipient,subject,body,message_type) VALUES(?,?,?,?,?)',[$userId,$recipient,$subject,$body,$type]);
        return $this->db->lastInsertId();
    }

    public function dispatch(int $limit=50): array
    {
        $limit=max(1,min(200,$limit));$sent=0;$failed=0;
        $rows=$this->db->all("SELECT * FROM email_outbox WHERE status='pending' AND (next_attempt_at IS NULL OR next_attempt_at<=NOW()) ORDER BY id LIMIT {$limit}");
        foreach($rows as $row){
            $ok=false;$error=null;
            try{
                $transport=(string)($this->config['mail']['transport']??'php_mail');
                if($transport==='log'){
                    $dir=dirname(__DIR__).'/var';if(!is_dir($dir))@mkdir($dir,0750,true);
                    $ok=file_put_contents($dir.'/mail.log',"TO: {$row['recipient']}\nSUBJECT: {$row['subject']}\n{$row['body']}\n---\n",FILE_APPEND|LOCK_EX)!==false;
                }else{
                    $headers=['Content-Type: text/plain; charset=UTF-8'];
                    if(!empty($this->config['mail']['from']))$headers[]='From: '.$this->config['mail']['from'];
                    $ok=@mail((string)$row['recipient'],(string)$row['subject'],(string)$row['body'],implode("\r\n",$headers));
                }
            }catch(\Throwable $e){$error=$e->getMessage();}
            if($ok){$this->db->execute("UPDATE email_outbox SET status='sent',attempt=attempt+1,sent_at=NOW(),last_error=NULL WHERE id=?",[(int)$row['id']]);$sent++;}
            else{$attempt=(int)$row['attempt']+1;$status=$attempt>=5?'dead':'pending';$delay=min(3600,60*(2**min(5,$attempt)));$this->db->execute('UPDATE email_outbox SET status=?,attempt=?,last_error=?,next_attempt_at=DATE_ADD(NOW(),INTERVAL ? SECOND) WHERE id=?',[$status,$attempt,substr((string)($error??'delivery_failed'),0,500),$delay,(int)$row['id']]);$failed++;}
        }
        return ['sent'=>$sent,'failed'=>$failed];
    }
}
