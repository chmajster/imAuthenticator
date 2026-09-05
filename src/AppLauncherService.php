<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AppLauncherService
{
    public function __construct(private Database $db,private ApplicationAccessService $access) {}

    public function applications(int $userId): array
    {
        $apps=$this->db->all("SELECT a.*,COALESCE(p.favorite,0) AS favorite,COALESCE(p.sort_order,0) AS user_sort FROM applications a LEFT JOIN user_application_preferences p ON p.application_id=a.id AND p.user_id=? WHERE a.enabled=1 AND a.deleted_at IS NULL ORDER BY favorite DESC,user_sort,a.name",[$userId]);
        return array_values(array_filter($apps,fn(array $a):bool=>$this->access->hasAccess($userId,$a)));
    }

    public function preference(int $userId,int $applicationId,bool $favorite,int $sortOrder): void{$this->db->execute('INSERT INTO user_application_preferences(user_id,application_id,favorite,sort_order) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE favorite=VALUES(favorite),sort_order=VALUES(sort_order)',[$userId,$applicationId,$favorite?1:0,$sortOrder]);}
    public function categories(): array{return $this->db->all('SELECT * FROM application_categories ORDER BY sort_order,name');}
    public function assignCategory(int $applicationId,int $categoryId): void{$this->db->execute('INSERT IGNORE INTO application_category_assignments(application_id,category_id) VALUES(?,?)',[$applicationId,$categoryId]);}
}
