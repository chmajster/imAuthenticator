<?php
declare(strict_types=1);
namespace ImAuthenticator;
final class ApplicationAdminService
{
 public function __construct(private Database$db){}
 public function canManage(int$userId,int$appId,string$permission='manage'):bool{$u=$this->db->one('SELECT is_admin,enabled,lifecycle_status FROM users WHERE id=?',[$userId]);if(!$u||!(bool)$u['enabled']||$u['lifecycle_status']!=='active')return false;if((bool)$u['is_admin'])return true;$app=$this->db->one('SELECT organization_id FROM applications WHERE id=? AND deleted_at IS NULL',[$appId]);if(!$app)return false;if($app['organization_id']!==null&&$this->db->one("SELECT 1 FROM organization_memberships WHERE organization_id=? AND user_id=? AND role IN ('owner','admin') AND status='active' AND (valid_from IS NULL OR valid_from<=NOW()) AND (valid_until IS NULL OR valid_until>NOW())",[(int)$app['organization_id'],$userId]))return true;if($this->db->one('SELECT 1 FROM application_owners WHERE application_id=? AND user_id=?',[$appId,$userId]))return true;$row=$this->db->one('SELECT permissions_json FROM application_admins WHERE application_id=? AND user_id=?',[$appId,$userId]);if(!$row)return false;$p=json_decode((string)$row['permissions_json'],true);if(!is_array($p))return false;if(($p['*']??false)===true||($p['manage']??false)===true)return true;if($permission==='manage')foreach($p as$v)if($v===true)return true;return($p[$permission]??false)===true;}
}
