<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class SchedulerService
{
    public function __construct(
        private Database $db,
        private HousekeepingService $housekeeping,
        private DeliveryService $delivery,
        private MailQueueService $mail,
        private SecretExpiryService $secretExpiry,
        private SigningKeyService $signingKeys,
        private DirectorySyncService $directory,
        private ScimOutboundService $scimOutbound,
        private AuditLog $audit
    ) {}

    public function refreshDiscoveredJobs(): void
    {
        $this->ensureJob('system:secret-expiry','secret_expiry',null,null,86400,0);
        $this->ensureJob('system:housekeeping','housekeeping',null,null,3600,0);
        $this->ensureJob('system:delivery','delivery',null,null,60,0);
        $this->ensureJob('system:mail','mail',null,null,60,0);
        $this->ensureJob('system:signing-key-rotation','signing_key_rotation',null,null,7776000,7776000);

        $this->db->execute("UPDATE scheduled_jobs SET enabled=0 WHERE job_type IN ('directory_sync','scim_outbound_sync')");
        foreach($this->db->all("SELECT id,config_json FROM identity_providers WHERE enabled=1 AND provider_type IN ('ldap','active_directory')") as $p){
            $cfg=json_decode((string)$p['config_json'],true);$minutes=max(0,(int)(is_array($cfg)?($cfg['sync_interval_minutes']??60):60));
            if($minutes>0)$this->ensureJob('directory:'.(int)$p['id'],'directory_sync','identity_provider',(int)$p['id'],max(300,$minutes*60),0);
        }
        foreach($this->db->all("SELECT id,mapping_json FROM scim_connectors WHERE enabled=1 AND direction='outbound'") as $c){
            $cfg=json_decode((string)$c['mapping_json'],true);$minutes=max(0,(int)(is_array($cfg)?($cfg['sync_interval_minutes']??15):15));
            if($minutes>0)$this->ensureJob('scim:'.(int)$c['id'],'scim_outbound_sync','scim_connector',(int)$c['id'],max(300,$minutes*60),0);
        }
    }

    public function runDue(int $limit=50): array
    {
        $lock=$this->db->one("SELECT GET_LOCK('imauthenticator_scheduler',0) AS l");
        if((int)($lock['l']??0)!==1)return ['locked'=>true,'executed'=>0,'success'=>0,'failed'=>0];
        $executed=0;$success=0;$failed=0;$details=[];
        try{
            $this->refreshDiscoveredJobs();
            $limit=max(1,min(200,$limit));
            $jobs=$this->db->all("SELECT * FROM scheduled_jobs WHERE enabled=1 AND (next_run_at IS NULL OR next_run_at<=NOW()) ORDER BY id LIMIT {$limit}");
            foreach($jobs as $job){
                $executed++;$interval=$this->intervalSeconds((string)$job['schedule_expression']);$next=date('Y-m-d H:i:s',time()+$interval);
                $this->db->execute('UPDATE scheduled_jobs SET last_run_at=NOW(),next_run_at=? WHERE id=?',[$next,(int)$job['id']]);
                try{$result=$this->execute($job);$json=json_encode($result,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);$this->db->execute("UPDATE scheduled_jobs SET last_status='success',last_error=NULL,last_result_json=? WHERE id=?",[$json,(int)$job['id']]);$success++;$details[(string)$job['job_key']]=['status'=>'success','result'=>$result];}
                catch(\Throwable $e){$msg=substr($e->getMessage(),0,500);$this->db->execute("UPDATE scheduled_jobs SET last_status='failure',last_error=?,last_result_json=NULL WHERE id=?",[$msg,(int)$job['id']]);$this->audit->write('scheduler.job.failed','failure',null,null,null,$msg,['job_key'=>$job['job_key'],'job_type'=>$job['job_type']]);$failed++;$details[(string)$job['job_key']]=['status'=>'failure','error'=>$msg];}
            }
        }finally{$this->db->one("SELECT RELEASE_LOCK('imauthenticator_scheduler') AS l");}
        return ['locked'=>false,'executed'=>$executed,'success'=>$success,'failed'=>$failed,'jobs'=>$details];
    }

    public function intervalSeconds(string $expression): int
    {
        if(!preg_match('/^every:([0-9]{1,9})$/',$expression,$m))throw new \RuntimeException('invalid_schedule_expression');
        return max(60,min(31536000,(int)$m[1]));
    }

    private function execute(array $job): array
    {
        return match((string)$job['job_type']){
            'secret_expiry'=>$this->secretExpiry->scan(),
            'housekeeping'=>$this->housekeeping->run($this->systemActorId()),
            'delivery'=>$this->delivery->dispatch(200),
            'mail'=>$this->mail->dispatch(200),
            'signing_key_rotation'=>$this->rotateKeys(),
            'directory_sync'=>$this->directory->sync((int)$job['resource_id'],$this->systemActorId()),
            'scim_outbound_sync'=>$this->scimOutbound->sync((int)$job['resource_id'],$this->systemActorId()),
            default=>throw new \RuntimeException('unknown_job_type')
        };
    }

    private function rotateKeys(): array
    {
        $result=$this->signingKeys->rotate($this->systemActorId(),7200);$result['retired']=$this->signingKeys->retireExpired();return$result;
    }

    private function systemActorId(): int
    {
        $row=$this->db->one("SELECT id FROM users WHERE is_admin=1 AND enabled=1 AND lifecycle_status='active' ORDER BY id LIMIT 1");
        if(!$row)throw new \RuntimeException('scheduler_admin_actor_missing');
        return(int)$row['id'];
    }

    private function ensureJob(string$key,string$type,?string$resourceType,?int$resourceId,int$seconds,int$initialDelay):void
    {
        $seconds=max(60,min(31536000,$seconds));$next=date('Y-m-d H:i:s',time()+max(0,$initialDelay));
        $this->db->execute("INSERT INTO scheduled_jobs(job_key,job_type,resource_type,resource_id,schedule_expression,enabled,next_run_at) VALUES(?,?,?,?,?,1,?) ON DUPLICATE KEY UPDATE job_type=VALUES(job_type),resource_type=VALUES(resource_type),resource_id=VALUES(resource_id),schedule_expression=VALUES(schedule_expression),enabled=1,next_run_at=COALESCE(next_run_at,VALUES(next_run_at))",[$key,$type,$resourceType,$resourceId,'every:'.$seconds,$next]);
    }
}
