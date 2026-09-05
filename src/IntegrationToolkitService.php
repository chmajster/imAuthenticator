<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class IntegrationToolkitService
{
    public function __construct(private Database $db,private array $config) {}

    public function templates(): array{return $this->db->all('SELECT * FROM application_templates WHERE enabled=1 ORDER BY name');}

    public function snippets(array $app): array
    {
        $issuer=rtrim((string)$this->config['issuer'],'/');$client=(string)$app['client_id'];$redirect=$this->db->one('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id LIMIT 1',[(int)$app['id']])['redirect_uri']??'';
        return [
            'php'=>"// league/oauth2-client or any OIDC client\n\$issuer = '".$issuer."';\n\$clientId = '".$client."';\n\$redirectUri = '".$redirect."';",
            'python'=>"ISSUER = '".$issuer."'\nCLIENT_ID = '".$client."'\nREDIRECT_URI = '".$redirect."'",
            'node'=>"const issuer = '".$issuer."';\nconst clientId = '".$client."';\nconst redirectUri = '".$redirect."';",
            'nginx'=>"location /oauth/callback {\n    proxy_set_header X-Forwarded-Proto https;\n    proxy_pass http://app;\n}",
            'apache'=>"RewriteEngine On\n# Callback: ".$redirect,
        ];
    }

    public function runDiagnostics(int $applicationId,?int $actorUserId=null): int
    {
        $app=$this->db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL',[$applicationId]);if(!$app)throw new \RuntimeException('not_found');$this->db->execute('INSERT INTO integration_diagnostic_runs(application_id,started_by) VALUES(?,?)',[$applicationId,$actorUserId]);$run=$this->db->lastInsertId();$checks=[];
        $checks[]=['client_enabled',(bool)$app['enabled']?'success':'failure',(bool)$app['enabled']?'Klient aktywny':'Klient wyłączony'];
        $redirects=$this->db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=?',[$applicationId]);$checks[]=['redirect_uri',$app['integration_type']==='client_credentials'||$redirects!==[]?'success':'failure','Redirect URI: '.count($redirects)];
        $checks[]=['discovery','success',rtrim((string)$this->config['issuer'],'/').'/.well-known/openid-configuration'];
        $checks[]=['client_secret',$app['client_type']==='public'||!empty($app['client_secret_hash'])?'success':'failure',$app['client_type']==='public'?'Public client':'Confidential client'];
        $status='success';foreach($checks as [$name,$s,$detail]){$this->db->execute('INSERT INTO integration_diagnostic_checks(run_id,check_name,status,detail) VALUES(?,?,?,?)',[$run,$name,$s,$detail]);if($s==='failure')$status='failure';}
        $this->db->execute('UPDATE integration_diagnostic_runs SET status=?,finished_at=NOW() WHERE id=?',[$status,$run]);return $run;
    }
}
