<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class DirectorySyncService
{
    public function __construct(private Database $db, private AuditLog $audit, private EventService $events) {}

    public function test(int $providerId): array
    {
        [$provider, $cfg] = $this->provider($providerId);
        $started = microtime(true);
        $link = $this->connect($cfg);
        $baseDn = trim((string)($cfg['base_dn'] ?? ''));
        if ($baseDn === '') throw new RuntimeException('base_dn_required');
        $result = @ldap_read($link, $baseDn, '(objectClass=*)', ['dn'], 0, 1, 5);
        if ($result === false) throw new RuntimeException('ldap_base_dn_unavailable');
        return [
            'ok' => true,
            'provider' => $provider['name'],
            'type' => $provider['provider_type'],
            'base_dn' => $baseDn,
            'latency_ms' => (int)round((microtime(true) - $started) * 1000),
        ];
    }

    public function sync(int $providerId, int $actorUserId): array
    {
        [$provider, $cfg] = $this->provider($providerId);
        $this->db->execute("INSERT INTO directory_sync_runs(identity_provider_id,status) VALUES(?,'running')", [$providerId]);
        $runId = $this->db->lastInsertId();
        $stats = ['created'=>0,'updated'=>0,'disabled'=>0,'groups'=>0];

        try {
            $link = $this->connect($cfg);
            $baseDn = trim((string)($cfg['base_dn'] ?? ''));
            $userBaseDn = trim((string)($cfg['user_base_dn'] ?? $baseDn));
            $userFilter = trim((string)($cfg['user_filter'] ?? '(objectClass=person)'));
            if ($baseDn === '' || $userBaseDn === '') throw new RuntimeException('base_dn_required');
            $limit = max(1, min((int)($cfg['max_users'] ?? 5000), 20000));
            $attrs = array_values(array_unique(array_map('strval', (array)($cfg['user_attributes'] ?? ['mail','uid','cn','displayName','sAMAccountName','objectGUID','department']))));
            $search = @ldap_search($link, $userBaseDn, $userFilter, $attrs, 0, $limit, 15);
            if ($search === false) throw new RuntimeException('ldap_user_search_failed');
            $entries = ldap_get_entries($link, $search);
            if (!is_array($entries)) throw new RuntimeException('ldap_user_read_failed');

            $seenSubjects = [];
            $dnToUser = [];
            for ($i = 0; $i < (int)($entries['count'] ?? 0); $i++) {
                $entry = $entries[$i];
                $dn = (string)($entry['dn'] ?? '');
                $email = strtolower(trim($this->first($entry, (string)($cfg['email_attribute'] ?? 'mail'))));
                $username = trim($this->first($entry, (string)($cfg['username_attribute'] ?? ($provider['provider_type'] === 'active_directory' ? 'sAMAccountName' : 'uid'))));
                $displayName = trim($this->first($entry, (string)($cfg['name_attribute'] ?? 'displayName')));
                if ($displayName === '') $displayName = trim($this->first($entry, 'cn'));
                if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) continue;
                if ($username === '') $username = strstr($email, '@', true) ?: $email;

                $subjectAttr = (string)($cfg['subject_attribute'] ?? ($provider['provider_type'] === 'active_directory' ? 'objectGUID' : 'entryUUID'));
                $rawSubject = $this->rawFirst($entry, $subjectAttr);
                $subject = $rawSubject !== '' ? $this->safeSubject($rawSubject) : $dn;
                if ($subject === '') continue;
                $seenSubjects[] = $subject;

                $identity = $this->db->one('SELECT user_id FROM external_identities WHERE identity_provider_id=? AND external_subject=?', [$providerId,$subject]);
                $userId = $identity ? (int)$identity['user_id'] : 0;
                if ($userId < 1) {
                    $existing = $this->db->one('SELECT id FROM users WHERE LOWER(email)=LOWER(?) OR LOWER(username)=LOWER(?) LIMIT 1', [$email,$username]);
                    $userId = $existing ? (int)$existing['id'] : 0;
                }

                if ($userId < 1) {
                    $this->db->execute(
                        "INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",
                        [Security::uuidV4(),$displayName !== '' ? $displayName : $username,$username,$email,password_hash(Security::randomToken(64),PASSWORD_ARGON2ID)]
                    );
                    $userId = $this->db->lastInsertId();
                    $stats['created']++;
                } else {
                    $this->db->execute("UPDATE users SET name=?,username=?,email=?,enabled=1,lifecycle_status=CASE WHEN lifecycle_status IN ('suspended','expired') THEN 'active' ELSE lifecycle_status END WHERE id=?", [$displayName !== '' ? $displayName : $username,$username,$email,$userId]);
                    $stats['updated']++;
                }

                $profile = ['dn'=>$dn,'synced_at'=>gmdate(DATE_ATOM)];
                $this->db->execute(
                    'INSERT INTO external_identities(user_id,identity_provider_id,external_subject,external_username,profile_json) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),external_username=VALUES(external_username),profile_json=VALUES(profile_json)',
                    [$userId,$providerId,$subject,$username,json_encode($profile,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)]
                );
                $dnToUser[strtolower($dn)] = $userId;
                foreach ((array)($cfg['attribute_mapping'] ?? ['department'=>'department']) as $source => $target) {
                    $value = $this->first($entry,(string)$source);
                    if ($value === '') continue;
                    $this->db->execute(
                        "INSERT INTO user_attributes(user_id,attribute_key,attribute_value,source) VALUES(?,?,?,'ldap') ON DUPLICATE KEY UPDATE attribute_value=VALUES(attribute_value),source=VALUES(source)",
                        [$userId,(string)$target,$value]
                    );
                }
            }

            if ((bool)($cfg['sync_groups'] ?? true)) {
                $stats['groups'] = $this->syncGroups($link,$provider,$cfg,$dnToUser);
            }

            if ((bool)($cfg['authoritative'] ?? false) && (bool)($cfg['disable_missing_users'] ?? false)) {
                $stats['disabled'] = $this->disableMissing($providerId,$seenSubjects,$actorUserId);
            }

            $this->db->execute("UPDATE directory_sync_runs SET status='success',users_created=?,users_updated=?,users_disabled=?,groups_updated=?,finished_at=NOW() WHERE id=?", [$stats['created'],$stats['updated'],$stats['disabled'],$stats['groups'],$runId]);
            $this->audit->write('directory.sync.success','success',$actorUserId,null,null,null,['provider_id'=>$providerId,'run_id'=>$runId]+$stats);
            $this->events->emit('directory.sync.completed',['provider_id'=>$providerId,'run_id'=>$runId]+$stats,$provider['organization_id']!==null?(int)$provider['organization_id']:null);
            return ['run_id'=>$runId]+$stats;
        } catch (\Throwable $e) {
            $this->db->execute("UPDATE directory_sync_runs SET status='failed',error_summary=?,finished_at=NOW() WHERE id=?", [substr($e->getMessage(),0,2000),$runId]);
            $this->audit->write('directory.sync.failed','failure',$actorUserId,null,null,$e->getMessage(),['provider_id'=>$providerId,'run_id'=>$runId]);
            throw $e;
        }
    }

    private function provider(int $providerId): array
    {
        $provider = $this->db->one("SELECT * FROM identity_providers WHERE id=? AND enabled=1 AND provider_type IN ('ldap','active_directory')", [$providerId]);
        if (!$provider) throw new RuntimeException('directory_provider_not_found');
        $cfg = json_decode((string)$provider['config_json'], true);
        if (!is_array($cfg)) throw new RuntimeException('invalid_directory_config');
        return [$provider,$cfg];
    }

    private function connect(array $cfg): \LDAP\Connection
    {
        if (!extension_loaded('ldap')) throw new RuntimeException('ldap_extension_missing');
        $uri = trim((string)($cfg['uri'] ?? ''));
        if (!preg_match('#^ldaps?://[A-Za-z0-9._:-]+$#i', $uri)) throw new RuntimeException('invalid_ldap_uri');
        $link = @ldap_connect($uri);
        if (!$link) throw new RuntimeException('ldap_connect_failed');
        ldap_set_option($link, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($link, LDAP_OPT_REFERRALS, (int)((bool)($cfg['follow_referrals'] ?? false)));
        if (defined('LDAP_OPT_NETWORK_TIMEOUT')) ldap_set_option($link, LDAP_OPT_NETWORK_TIMEOUT, max(1,min((int)($cfg['timeout_seconds'] ?? 5),30)));
        if ((bool)($cfg['start_tls'] ?? false)) {
            if (!str_starts_with(strtolower($uri), 'ldap://') || !@ldap_start_tls($link)) throw new RuntimeException('ldap_starttls_failed');
        }
        $bindDn = (string)($cfg['bind_dn'] ?? '');
        $password = '';
        $passwordEnv = trim((string)($cfg['bind_password_env'] ?? ''));
        if ($passwordEnv !== '') {
            $env = getenv($passwordEnv);
            if ($env === false) throw new RuntimeException('ldap_bind_password_env_missing');
            $password = $env;
        }
        if (!@ldap_bind($link,$bindDn,$password)) throw new RuntimeException('ldap_bind_failed');
        return $link;
    }

    private function syncGroups(\LDAP\Connection $link,array $provider,array $cfg,array $dnToUser): int
    {
        $base = trim((string)($cfg['group_base_dn'] ?? $cfg['base_dn'] ?? ''));
        $filter = trim((string)($cfg['group_filter'] ?? ($provider['provider_type']==='active_directory'?'(objectClass=group)':'(objectClass=groupOfNames)')));
        $nameAttr = (string)($cfg['group_name_attribute'] ?? 'cn');
        $memberAttr = (string)($cfg['group_member_attribute'] ?? 'member');
        $search = @ldap_search($link,$base,$filter,[$nameAttr,$memberAttr,'objectGUID','entryUUID'],0,max(1,min((int)($cfg['max_groups']??2000),10000)),15);
        if ($search === false) throw new RuntimeException('ldap_group_search_failed');
        $entries = ldap_get_entries($link,$search);$updated=0;
        for($i=0;$i<(int)($entries['count']??0);$i++){
            $entry=$entries[$i];$name=trim($this->first($entry,$nameAttr));if($name==='')continue;
            $extRaw=$this->rawFirst($entry,$provider['provider_type']==='active_directory'?'objectGUID':'entryUUID');$external=$extRaw!==''?$this->safeSubject($extRaw):(string)($entry['dn']??$name);
            $group=$this->db->one('SELECT id FROM user_groups WHERE name=?',[$name]);if(!$group){$this->db->execute('INSERT INTO user_groups(name,description) VALUES(?,?)',[$name,'Directory sync: '.$provider['name']]);$groupId=$this->db->lastInsertId();}else$groupId=(int)$group['id'];
            $members=$this->values($entry,$memberAttr);$memberIds=[];foreach($members as $memberDn){$key=strtolower($memberDn);if(isset($dnToUser[$key]))$memberIds[]=(int)$dnToUser[$key];}
            if($memberIds!==[]){$marks=implode(',',array_fill(0,count($memberIds),'?'));$this->db->execute("DELETE FROM group_members WHERE group_id=? AND user_id NOT IN ({$marks})",array_merge([$groupId],$memberIds));foreach($memberIds as $uid)$this->db->execute('INSERT IGNORE INTO group_members(group_id,user_id) VALUES(?,?)',[$groupId,$uid]);}
            $updated++;
        }
        return $updated;
    }

    private function disableMissing(int $providerId,array $subjects,int $actorUserId): int
    {
        $rows=$this->db->all('SELECT user_id,external_subject FROM external_identities WHERE identity_provider_id=?',[$providerId]);$disabled=0;$seen=array_fill_keys($subjects,true);
        foreach($rows as $row){if(isset($seen[(string)$row['external_subject']]))continue;$userId=(int)$row['user_id'];$other=$this->db->one('SELECT COUNT(*) AS c FROM external_identities WHERE user_id=? AND identity_provider_id<>?',[$userId,$providerId]);if((int)($other['c']??0)>0)continue;$this->db->execute("UPDATE users SET enabled=0,lifecycle_status='suspended' WHERE id=?",[$userId]);$this->audit->write('directory.user.suspended','success',$actorUserId,$userId,null,'missing from authoritative directory',['provider_id'=>$providerId]);$disabled++;}
        return $disabled;
    }

    private function first(array $entry,string $attribute): string { $key=strtolower($attribute);$value=$entry[$key][0]??$entry[$attribute][0]??'';return is_string($value)?trim($value):''; }
    private function rawFirst(array $entry,string $attribute): string { $key=strtolower($attribute);$value=$entry[$key][0]??$entry[$attribute][0]??'';return is_string($value)?$value:''; }
    private function values(array $entry,string $attribute): array { $key=strtolower($attribute);$values=$entry[$key]??$entry[$attribute]??[];$out=[];if(!is_array($values))return$out;for($i=0;$i<(int)($values['count']??0);$i++)if(is_string($values[$i]??null))$out[]=$values[$i];return$out; }
    private function safeSubject(string $value): string { if(preg_match('//u',$value)===1&&preg_match('/^[\pL\pN._:@-]+$/u',$value))return$value;return'bin:'.rtrim(strtr(base64_encode($value),'+/','-_'),'='); }
}
