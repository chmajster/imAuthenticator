<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ApplicationAdminService
{
    public function __construct(private Database $db) {}

    public function canManage(int $userId, int $applicationId, string $permission = 'manage'): bool
    {
        $user = $this->db->one('SELECT is_admin,enabled,lifecycle_status FROM users WHERE id=?', [$userId]);
        if (!$user || !(bool)$user['enabled'] || $user['lifecycle_status'] !== 'active') return false;
        if ((bool)$user['is_admin']) return true;
        if ($this->db->one('SELECT 1 FROM application_owners WHERE application_id=? AND user_id=?', [$applicationId,$userId])) return true;
        $row = $this->db->one('SELECT permissions_json FROM application_admins WHERE application_id=? AND user_id=?', [$applicationId,$userId]);
        if (!$row) return false;
        $permissions = json_decode((string)$row['permissions_json'], true);
        if(!is_array($permissions))return false;
        if(($permissions['*']??false)===true||($permissions['manage']??false)===true)return true;
        if($permission==='manage')foreach($permissions as $value)if($value===true)return true;
        return ($permissions[$permission] ?? false) === true;
    }
}
