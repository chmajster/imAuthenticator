<?php
declare(strict_types=1);

use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireAdmin();
$failed = $db->one("SELECT COUNT(*) AS c FROM login_events WHERE event_type='login_failure' AND created_at>DATE_SUB(NOW(),INTERVAL 24 HOUR)");
$highRisk = $db->one("SELECT COUNT(*) AS c FROM login_events WHERE risk_score>=70 AND created_at>DATE_SUB(NOW(),INTERVAL 24 HOUR)");
$sessions = $db->one('SELECT COUNT(*) AS c FROM oidc_sessions WHERE revoked_at IS NULL');
$devices = $db->one('SELECT COUNT(*) AS c FROM user_devices WHERE revoked_at IS NULL');
$pending = $db->one("SELECT COUNT(*) AS c FROM access_requests WHERE status='pending'");
$integrity = $auditIntegrity->verify();
$events = $db->all('SELECT le.*,u.email,a.name AS app_name FROM login_events le LEFT JOIN users u ON u.id=le.user_id LEFT JOIN applications a ON a.id=le.application_id ORDER BY le.created_at DESC LIMIT 50');
$rows = '';
foreach ($events as $event) $rows .= '<tr><td>'.Web::e($event['created_at']).'</td><td>'.Web::e($event['email'] ?: '—').'</td><td>'.Web::e($event['app_name'] ?: '—').'</td><td>'.Web::e($event['event_type']).'</td><td>'.(int)$event['risk_score'].'</td><td>'.Web::e($event['ip_address'] ?: '—').'</td></tr>';
$content = '<div class="page-head"><div><h1>Security dashboard</h1><p>Stan uwierzytelniania, sesji i ryzyka.</p></div><a class="button" href="/admin/audit/export?format=csv">Eksport audytu CSV</a></div><div class="app-grid"><section class="card"><h2>'.(int)$failed['c'].'</h2><p>Nieudane logowania / 24h</p></section><section class="card"><h2>'.(int)$highRisk['c'].'</h2><p>Zdarzenia wysokiego ryzyka / 24h</p></section><section class="card"><h2>'.(int)$sessions['c'].'</h2><p>Aktywne sesje OIDC</p></section><section class="card"><h2>'.(int)$devices['c'].'</h2><p>Aktywne urządzenia</p></section><section class="card"><h2>'.(int)$pending['c'].'</h2><p>Wnioski oczekujące</p></section><section class="card"><h2>'.(($integrity['valid']??false)?'OK':'BŁĄD').'</h2><p>Integralność Audit Log</p></section></div><div class="table-wrap"><table><thead><tr><th>Data</th><th>Użytkownik</th><th>Aplikacja</th><th>Zdarzenie</th><th>Risk</th><th>IP</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Security dashboard',$content,$user);
