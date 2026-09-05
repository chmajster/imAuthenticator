<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class LogoutPropagationService
{
    public function __construct(private Database $db,private AuditLog $audit,private JwtService $jwt) {}

    public function propagate(int $userId): array
    {
        $rows=$this->db->all("SELECT s.sid,a.id AS application_id,a.name,a.client_id,a.frontchannel_logout_uri,a.backchannel_logout_uri,a.backchannel_logout_session_required FROM oidc_sessions s JOIN applications a ON a.id=s.application_id WHERE s.user_id=? AND s.revoked_at IS NULL AND a.deleted_at IS NULL",[$userId]);
        $front=[];$seenFront=[];
        foreach($rows as $row){
            $sid=(string)$row['sid'];$appId=(int)$row['application_id'];
            $frontUri=trim((string)($row['frontchannel_logout_uri']??''));
            if($frontUri!==''&&Security::validRedirectUri($frontUri)){
                $url=$frontUri.(str_contains($frontUri,'?')?'&':'?').http_build_query(['iss'=>$this->jwt->issuer(),'sid'=>$sid]);
                $key=$appId.'|'.$url;if(!isset($seenFront[$key])){$front[]=$url;$seenFront[$key]=true;$this->record($appId,$userId,$sid,'front',$frontUri,'pending');}
            }
            $backUri=trim((string)($row['backchannel_logout_uri']??''));
            if($backUri!==''&&Security::validRedirectUri($backUri))$this->sendBackChannel($row,$userId,$sid,$backUri);
        }
        return array_values(array_unique($front));
    }

    private function sendBackChannel(array $row,int $userId,string $sid,string $endpoint): void
    {
        $claims=['iss'=>$this->jwt->issuer(),'aud'=>(string)$row['client_id'],'iat'=>time(),'jti'=>Security::randomToken(24),'events'=>['http://schemas.openid.net/event/backchannel-logout'=>new \stdClass()]];
        if((bool)$row['backchannel_logout_session_required'])$claims['sid']=$sid;
        $token=$this->jwt->sign($claims,['typ'=>'logout+jwt']);$body=http_build_query(['logout_token'=>$token]);$status='failure';$code=null;$error=null;
        try{
            $context=stream_context_create(['http'=>['method'=>'POST','header'=>"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n",'content'=>$body,'timeout'=>3,'ignore_errors'=>true],'ssl'=>['verify_peer'=>true,'verify_peer_name'=>true]]);
            $result=@file_get_contents($endpoint,false,$context);$headers=$http_response_header??[];foreach($headers as $header)if(preg_match('#^HTTP/\S+\s+(\d{3})#',$header,$m)){$code=(int)$m[1];break;}$status=$code!==null&&$code>=200&&$code<300?'success':'failure';if($status==='failure')$error=$code===null?'delivery_failed':'HTTP '.$code;
        }catch(\Throwable $e){$error=substr($e->getMessage(),0,500);}
        $this->record((int)$row['application_id'],$userId,$sid,'back',$endpoint,$status,$code,$error);
        $this->audit->write('oidc.backchannel_logout.'.$status,$status==='success'?'success':'failure',$userId,$userId,(int)$row['application_id'],$error,['http_status'=>$code]);
    }

    private function record(int $appId,int $userId,string $sid,string $channel,string $endpoint,string $status,?int $code=null,?string $error=null): void
    {
        $this->db->execute('INSERT INTO logout_deliveries(application_id,user_id,sid,channel,endpoint_url,status,response_code,error_message,delivered_at) VALUES(?,?,?,?,?,?,?,?,IF(? IN (\'success\',\'failure\',\'skipped\'),NOW(),NULL))',[$appId,$userId,$sid,$channel,$endpoint,$status,$code,$error,$status]);
    }
}
