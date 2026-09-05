<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class SystemSettingsService
{
    public function __construct(private Database $db, private AuditLog $audit) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $row = $this->db->one('SELECT value_json FROM system_settings WHERE setting_key=?', [$key]);
        if (!$row) return $default;
        try { return json_decode((string)$row['value_json'], true, 512, JSON_THROW_ON_ERROR); }
        catch (\Throwable) { return $default; }
    }

    public function set(string $key, mixed $value, int $actorUserId): void
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
        $this->db->execute('INSERT INTO system_settings(setting_key,value_json,updated_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE value_json=VALUES(value_json),updated_by=VALUES(updated_by),updated_at=NOW()', [$key,$json,$actorUserId]);
        $this->audit->write('system.setting.updated','success',$actorUserId,null,null,null,['setting'=>$key]);
    }

    public function maintenanceMode(): bool { return (bool)$this->get('maintenance_mode', false); }
    public function externalLoginEmergencyDisabled(): bool { return (bool)$this->get('external_login_emergency_disabled', false); }
    public function announcement(): ?string { $v=$this->get('announcement_banner'); return is_string($v)&&trim($v)!==''?trim($v):null; }
    public function inactiveDays(): int { return max(0,(int)$this->get('inactive_account_days',90)); }
    public function auditRetentionDays(): int { return max(0,(int)$this->get('audit_retention_days',365)); }
}
