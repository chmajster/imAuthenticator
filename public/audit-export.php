<?php
declare(strict_types=1);

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$auth->requireAdmin();
$format = strtolower((string)($_GET['format'] ?? 'json'));
$rows = $db->all('SELECT id,created_at,action,result,actor_user_id,subject_user_id,application_id,organization_id,reason,ip_address,metadata_json,previous_hash,entry_hash FROM audit_log ORDER BY id DESC LIMIT 10000');
header('Cache-Control: no-store');
if ($format === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="imauthenticator-audit.csv"');
    $out = fopen('php://output','wb');
    fputcsv($out,array_keys($rows[0] ?? ['id'=>null,'created_at'=>null,'action'=>null]));
    foreach ($rows as $row) fputcsv($out,$row);
    fclose($out);
    exit;
}
header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="imauthenticator-audit.json"');
echo json_encode(['integrity'=>$auditIntegrity->verify(),'events'=>$rows], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
