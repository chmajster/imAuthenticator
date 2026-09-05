<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class SecretExpiryService
{
    public function __construct(private Database $db, private MailQueueService $mail, private EventService $events, private AuditLog $audit) {}

    public function scan(): array
    {
        $rows = $this->db->all("SELECT cs.*,a.name AS application_name,a.organization_id FROM client_secrets cs JOIN applications a ON a.id=cs.application_id WHERE cs.revoked_at IS NULL AND cs.valid_until IS NOT NULL AND cs.valid_until>NOW() AND cs.id=(SELECT cs2.id FROM client_secrets cs2 WHERE cs2.application_id=cs.application_id AND cs2.revoked_at IS NULL AND cs2.valid_until IS NOT NULL AND cs2.valid_until>NOW() ORDER BY cs2.valid_from DESC,cs2.id DESC LIMIT 1) AND a.enabled=1 AND a.deleted_at IS NULL AND cs.valid_until<=DATE_ADD(NOW(),INTERVAL 30 DAY)");
        $queued=0;$events=0;
        foreach($rows as $row){
            $remaining=max(0,(int)ceil((strtotime((string)$row['valid_until'])-time())/86400));
            $threshold=null;foreach([7,14,30] as $candidate){if($remaining<=$candidate){$threshold=$candidate;break;}}
            if($threshold===null)continue;
            if($this->db->one('SELECT 1 FROM client_secret_expiry_notifications WHERE client_secret_id=? AND days_before=?',[(int)$row['id'],$threshold]))continue;
            $this->db->execute('INSERT IGNORE INTO client_secret_expiry_notifications(client_secret_id,days_before) VALUES(?,?)',[(int)$row['id'],$threshold]);
            $severity=$threshold<=7?'critical':($threshold<=14?'high':'warning');
            $payload=['application_id'=>(int)$row['application_id'],'application_name'=>(string)$row['application_name'],'secret_hint'=>(string)($row['secret_hint']??''),'valid_until'=>(string)$row['valid_until'],'days_remaining'=>$remaining,'threshold_days'=>$threshold,'severity'=>$severity];
            $this->events->emit('application.secret.expiring',$payload,$row['organization_id']!==null?(int)$row['organization_id']:null);$events++;
            foreach($this->recipients((int)$row['application_id']) as $recipient){
                $subject='imAuthenticator: client secret wygasa — '.$row['application_name'];
                $body="Client secret aplikacji {$row['application_name']} wygasa {$row['valid_until']} (pozostało około {$remaining} dni).\n\nClient ID/secret nie są dołączane do wiadomości. Zaloguj się do imAuthenticator i wykonaj bezpieczną rotację z okresem nakładania sekretów.";
                try{$this->mail->queue($recipient,$subject,$body,'client_secret_expiry');$queued++;}catch(\Throwable){}
            }
            $this->audit->write('application.secret.expiry_alert.queued','success',null,null,(int)$row['application_id'],null,$payload);
        }
        return ['secrets'=>count($rows),'events'=>$events,'emails_queued'=>$queued];
    }

    private function recipients(int $applicationId): array
    {
        $rows=$this->db->all("SELECT DISTINCT u.email FROM users u WHERE u.enabled=1 AND u.lifecycle_status='active' AND (u.id IN (SELECT user_id FROM application_owners WHERE application_id=?) OR u.id IN (SELECT user_id FROM application_admins WHERE application_id=? AND (JSON_EXTRACT(permissions_json,'$.manage_secrets')=true OR JSON_EXTRACT(permissions_json,'$.manage')=true OR JSON_EXTRACT(permissions_json,'$.*')=true)))",[$applicationId,$applicationId]);
        $emails=array_values(array_unique(array_filter(array_map(static fn(array$r)=>(string)$r['email'],$rows),static fn(string$e)=>filter_var($e,FILTER_VALIDATE_EMAIL)!==false)));
        if($emails!==[])return$emails;
        return array_values(array_unique(array_column($this->db->all("SELECT email FROM users WHERE is_admin=1 AND enabled=1 AND lifecycle_status='active'"),'email')));
    }
}
