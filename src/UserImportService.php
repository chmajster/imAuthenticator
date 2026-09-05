<?php
declare(strict_types=1);

namespace ImAuthenticator;

use DOMDocument;
use DOMXPath;
use RuntimeException;
use ZipArchive;

final class UserImportService
{
    public function __construct(private Database $db, private AuditLog $audit) {}

    public function importFile(string $path, string $fileName, string $format, int $actorUserId, string $duplicateMode = 'skip'): array
    {
        $format = strtolower($format);
        if (!in_array($format, ['csv','xlsx'], true)) throw new RuntimeException('unsupported_import_format');
        if (!is_file($path) || filesize($path) === false || filesize($path) > 10 * 1024 * 1024) throw new RuntimeException('invalid_import_file');
        $rows = $format === 'csv' ? $this->readCsv($path) : $this->readXlsx($path);
        return $this->importRows($rows, $fileName, $format, $actorUserId, $duplicateMode);
    }

    public function importRows(array $rows, string $fileName, string $format, int $actorUserId, string $duplicateMode = 'skip'): array
    {
        if (!in_array($duplicateMode, ['skip','update'], true)) throw new RuntimeException('invalid_duplicate_mode');
        $this->db->execute("INSERT INTO user_import_jobs(uuid,file_name,format,status,created_by) VALUES(?,?,?,'processing',?)", [Security::uuidV4(),substr($fileName,0,500),$format,$actorUserId]);
        $jobId=$this->db->lastInsertId();
        $summary=['created'=>0,'updated'=>0,'duplicate'=>0,'failed'=>0,'skipped'=>0,'rows'=>count($rows)];
        try {
            foreach ($rows as $index=>$raw) {
                $sourceRow=(int)($raw['_source_row']??($index+2));unset($raw['_source_row']);
                $this->db->execute("INSERT INTO user_import_rows(import_job_id,source_row,payload_json,status) VALUES(?,?,?,'pending')",[$jobId,$sourceRow,json_encode($raw,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)]);
                $importRowId=$this->db->lastInsertId();
                try {
                    $row=$this->normalizeRow($raw);
                    if($row['name']===''||!filter_var($row['email'],FILTER_VALIDATE_EMAIL))throw new RuntimeException('name_or_email_invalid');
                    $existing=$this->findExisting($row['email'],$row['username']);
                    if($existing&&$duplicateMode==='skip'){$summary['duplicate']++;$this->finishRow($importRowId,'duplicate',(int)$existing['id'],'Existing user matched by e-mail or username');continue;}
                    if($existing){$userId=(int)$existing['id'];$this->updateUser($userId,$row);$summary['updated']++;$status='updated';}
                    else{$userId=$this->createUser($row);$summary['created']++;$status='created';}
                    $warnings=$this->applyMembershipsAndAttributes($userId,$row);$this->finishRow($importRowId,$status,$userId,$warnings===[]?null:implode('; ',$warnings));
                } catch (\Throwable $e) {$summary['failed']++;$this->finishRow($importRowId,'failed',null,substr($e->getMessage(),0,500));}
            }
            $this->db->execute("UPDATE user_import_jobs SET status='completed',completed_at=NOW(),summary_json=? WHERE id=?",[json_encode($summary,JSON_THROW_ON_ERROR),$jobId]);
            $this->audit->write('users.import.completed','success',$actorUserId,null,null,null,['job_id'=>$jobId]+$summary);
            return ['job_id'=>$jobId,'summary'=>$summary];
        } catch (\Throwable $e) {
            $this->db->execute("UPDATE user_import_jobs SET status='failed',completed_at=NOW(),error_message=? WHERE id=?",[substr($e->getMessage(),0,500),$jobId]);
            $this->audit->write('users.import.failed','failure',$actorUserId,null,null,substr($e->getMessage(),0,500),['job_id'=>$jobId]);throw $e;
        }
    }

    private function createUser(array $row): int
    {
        $enabled=$row['enabled']?1:0;$status=$enabled?'active':'disabled';
        $this->db->execute('INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status,account_starts_at,account_ends_at) VALUES(?,?,?,?,?,?,?,?,?)',[Security::uuidV4(),$row['name'],$row['username']!==''?$row['username']:null,$row['email'],password_hash(Security::randomToken(64),PASSWORD_ARGON2ID),$enabled,$status,$row['starts_at'],$row['ends_at']]);
        $userId=$this->db->lastInsertId();
        $this->db->execute('INSERT INTO user_emails(user_id,email,is_primary,verified_at) VALUES(?,?,1,NULL)',[$userId,$row['email']]);
        $this->db->execute("INSERT INTO required_actions(user_id,action_type,payload_json) VALUES(?,'change_password',JSON_OBJECT())",[$userId]);
        $this->db->execute("INSERT INTO required_actions(user_id,action_type,payload_json) VALUES(?,'verify_email',JSON_OBJECT())",[$userId]);
        return $userId;
    }

    private function updateUser(int $userId,array $row): void
    {
        if($row['username']!==''){$collision=$this->db->one('SELECT id FROM users WHERE LOWER(username)=LOWER(?) AND id<>?',[$row['username'],$userId]);if($collision)throw new RuntimeException('username_collision');}
        $this->db->execute('UPDATE users SET name=?,username=COALESCE(NULLIF(?,\'\'),username),enabled=?,lifecycle_status=?,account_starts_at=?,account_ends_at=? WHERE id=?',[$row['name'],$row['username'],$row['enabled']?1:0,$row['enabled']?'active':'disabled',$row['starts_at'],$row['ends_at'],$userId]);
    }

    private function applyMembershipsAndAttributes(int $userId,array $row): array
    {
        $warnings=[];
        foreach($row['groups'] as $name){$group=$this->db->one('SELECT id FROM user_groups WHERE name=?',[$name]);if(!$group){$this->db->execute('INSERT INTO user_groups(name) VALUES(?)',[$name]);$group=['id'=>$this->db->lastInsertId()];}$this->db->execute('INSERT IGNORE INTO group_members(group_id,user_id) VALUES(?,?)',[(int)$group['id'],$userId]);}
        foreach($row['roles'] as $name){$role=$this->db->one('SELECT id FROM system_roles WHERE LOWER(name)=LOWER(?)',[$name]);if(!$role){$warnings[]='Unknown role: '.$name;continue;}$this->db->execute('INSERT IGNORE INTO user_system_roles(user_id,role_id) VALUES(?,?)',[$userId,(int)$role['id']]);}
        foreach($row['attributes'] as $key=>$value){if($key===''||strlen($key)>120)continue;$this->db->execute("INSERT INTO user_attributes(user_id,attribute_key,attribute_value,source) VALUES(?,?,?,'manual') ON DUPLICATE KEY UPDATE attribute_value=VALUES(attribute_value),source='manual'",[$userId,$key,(string)$value]);}
        return $warnings;
    }

    private function findExisting(string $email,string $username): ?array{if($username!=='')return $this->db->one('SELECT id FROM users WHERE LOWER(email)=LOWER(?) OR LOWER(username)=LOWER(?) LIMIT 1',[$email,$username]);return $this->db->one('SELECT id FROM users WHERE LOWER(email)=LOWER(?) LIMIT 1',[$email]);}
    private function finishRow(int $id,string $status,?int $userId,?string $message): void{$this->db->execute('UPDATE user_import_rows SET status=?,user_id=?,message=? WHERE id=?',[$status,$userId,$message,$id]);}

    private function normalizeRow(array $row): array
    {
        $normalized=[];foreach($row as $key=>$value){$k=$this->normalizeHeader((string)$key);$normalized[$k]=is_scalar($value)||$value===null?trim((string)$value):'';}
        $pick=static function(array $keys)use($normalized):string{foreach($keys as $key)if(isset($normalized[$key])&&$normalized[$key]!=='')return$normalized[$key];return'';};
        $bool=static function(string $value):bool{return !in_array(strtolower(trim($value)),['0','false','no','nie','disabled','inactive','wylaczony'],true);};
        $attributes=[];foreach($normalized as $key=>$value){if(str_starts_with($key,'attr.'))$attributes[substr($key,5)]=$value;elseif(str_starts_with($key,'attribute.'))$attributes[substr($key,10)]=$value;}
        return ['name'=>$pick(['name','nazwa','displayname','display_name']),'email'=>strtolower($pick(['email','e_mail','mail'])),'username'=>$pick(['username','login','user_name','uzytkownik']),'enabled'=>$bool($pick(['enabled','active','aktywny','status'])?:'true'),'starts_at'=>$this->dateOrNull($pick(['account_starts_at','starts_at','start_date','data_rozpoczecia'])),'ends_at'=>$this->dateOrNull($pick(['account_ends_at','ends_at','end_date','data_zakonczenia'])),'groups'=>$this->splitList($pick(['groups','grupy'])),'roles'=>$this->splitList($pick(['roles','role','role_systemowe'])),'attributes'=>$attributes];
    }

    private function normalizeHeader(string $header): string
    {
        $header=preg_replace('/^\xEF\xBB\xBF/','',$header)??$header;$header=mb_strtolower(trim($header));
        $header=strtr($header,['ą'=>'a','ć'=>'c','ę'=>'e','ł'=>'l','ń'=>'n','ó'=>'o','ś'=>'s','ź'=>'z','ż'=>'z']);
        return trim((string)(preg_replace('/[^a-z0-9.]+/u','_',$header)??$header),'_');
    }
    private function splitList(string $value): array{return array_values(array_unique(array_filter(array_map('trim',preg_split('/[;,|]+/',$value)?:[]))));}
    private function dateOrNull(string $value): ?string{if($value==='')return null;if(is_numeric($value)){ $n=(float)$value;if($n>20000&&$n<80000)return gmdate('Y-m-d H:i:s',(int)(($n-25569)*86400)); }$ts=strtotime($value);if($ts===false)throw new RuntimeException('invalid_date_'.$value);return date('Y-m-d H:i:s',$ts);}

    private function readCsv(string $path): array
    {
        $fh=fopen($path,'rb');if(!$fh)throw new RuntimeException('cannot_open_csv');$first=fgets($fh);if($first===false){fclose($fh);return[];}$counts=[];foreach([',',';',"\t"] as $delimiter)$counts[$delimiter]=substr_count($first,$delimiter);arsort($counts);$delimiter=(string)array_key_first($counts);rewind($fh);$headers=fgetcsv($fh,0,$delimiter);if(!is_array($headers)){fclose($fh);throw new RuntimeException('csv_header_missing');}$headers=array_map(fn($h)=>$this->normalizeHeader((string)$h),$headers);$rows=[];$line=1;while(($values=fgetcsv($fh,0,$delimiter))!==false){$line++;if(count(array_filter($values,static fn($v)=>trim((string)$v)!==''))===0)continue;$row=[];foreach($headers as $i=>$header)if($header!=='')$row[$header]=$values[$i]??'';$row['_source_row']=$line;$rows[]=$row;}fclose($fh);return$rows;
    }

    private function readXlsx(string $path): array
    {
        if(!class_exists(ZipArchive::class))throw new RuntimeException('zip_extension_required');$zip=new ZipArchive();if($zip->open($path)!==true)throw new RuntimeException('cannot_open_xlsx');
        try{$shared=$this->xlsxSharedStrings($zip);$sheetPath=$this->xlsxFirstSheetPath($zip);$xml=$zip->getFromName($sheetPath);if(!is_string($xml))throw new RuntimeException('xlsx_sheet_missing');$dom=$this->xml($xml);$xp=new DOMXPath($dom);$rowNodes=$xp->query('//*[local-name()="sheetData"]/*[local-name()="row"]');if(!$rowNodes)return[];$matrix=[];foreach($rowNodes as $rowNode){$cells=[];foreach($xp->query('./*[local-name()="c"]',$rowNode)?:[] as $cell){$ref=$cell->attributes?->getNamedItem('r')?->nodeValue??'';$col=$this->xlsxColumnIndex((string)$ref);$type=$cell->attributes?->getNamedItem('t')?->nodeValue??'';$value='';if($type==='inlineStr'){$parts=[];foreach($xp->query('.//*[local-name()="t"]',$cell)?:[] as $t)$parts[]=$t->textContent;$value=implode('',$parts);}else{$v=$xp->query('./*[local-name()="v"]',$cell)?->item(0)?->textContent??'';$value=$type==='s'?(string)($shared[(int)$v]??''):(string)$v;}$cells[$col]=$value;}$matrix[]=['row'=>(int)($rowNode->attributes?->getNamedItem('r')?->nodeValue??(count($matrix)+1)),'cells'=>$cells];}if($matrix===[])return[];$headerRow=array_shift($matrix);$headers=[];foreach($headerRow['cells'] as $i=>$h)$headers[$i]=$this->normalizeHeader((string)$h);$rows=[];foreach($matrix as $entry){$row=[];foreach($headers as $i=>$h)if($h!=='')$row[$h]=$entry['cells'][$i]??'';if(count(array_filter($row,static fn($v)=>trim((string)$v)!==''))===0)continue;$row['_source_row']=$entry['row'];$rows[]=$row;}return$rows;}finally{$zip->close();}
    }

    private function xlsxSharedStrings(ZipArchive $zip): array{$xml=$zip->getFromName('xl/sharedStrings.xml');if(!is_string($xml))return[];$dom=$this->xml($xml);$xp=new DOMXPath($dom);$result=[];foreach($xp->query('//*[local-name()="si"]')?:[] as $si){$parts=[];foreach($xp->query('.//*[local-name()="t"]',$si)?:[] as $t)$parts[]=$t->textContent;$result[]=implode('',$parts);}return$result;}
    private function xlsxFirstSheetPath(ZipArchive $zip): string{$workbook=$zip->getFromName('xl/workbook.xml');$rels=$zip->getFromName('xl/_rels/workbook.xml.rels');if(!is_string($workbook)||!is_string($rels))return'xl/worksheets/sheet1.xml';$wd=$this->xml($workbook);$xp=new DOMXPath($wd);$sheet=$xp->query('//*[local-name()="sheets"]/*[local-name()="sheet"][1]')?->item(0);if(!$sheet)return'xl/worksheets/sheet1.xml';$rid='';foreach($sheet->attributes??[] as $attr)if($attr->localName==='id'){$rid=$attr->nodeValue;break;}if($rid==='')return'xl/worksheets/sheet1.xml';$rd=$this->xml($rels);$rx=new DOMXPath($rd);foreach($rx->query('//*[local-name()="Relationship"]')?:[] as $rel)if(($rel->attributes?->getNamedItem('Id')?->nodeValue??'')===$rid){$target=(string)($rel->attributes?->getNamedItem('Target')?->nodeValue??'worksheets/sheet1.xml');return str_starts_with($target,'/')?ltrim($target,'/'):'xl/'.ltrim($target,'/');}return'xl/worksheets/sheet1.xml';}
    private function xlsxColumnIndex(string $reference): int{if(!preg_match('/^([A-Z]+)[0-9]+$/i',$reference,$m))return0;$n=0;foreach(str_split(strtoupper($m[1])) as $c)$n=$n*26+(ord($c)-64);return$n-1;}
    private function xml(string $xml): DOMDocument{$dom=new DOMDocument();if(!@$dom->loadXML($xml,LIBXML_NONET|LIBXML_NOERROR|LIBXML_NOWARNING))throw new RuntimeException('invalid_xlsx_xml');return$dom;}
}
