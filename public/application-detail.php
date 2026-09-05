<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
$appId = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
if (!$app) { http_response_code(404); Web::page('Nie znaleziono', '<div class="alert danger">Nie znaleziono aplikacji.</div>', $admin); }

$redirects = array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id', [$appId]), 'redirect_uri');
$scopes = array_column($db->all('SELECT scope FROM application_scopes WHERE application_id=? ORDER BY scope', [$appId]), 'scope');
$roles = $db->all('SELECT * FROM app_roles WHERE application_id=? ORDER BY name', [$appId]);
$groups = $db->all('SELECT g.*,ag.group_id AS selected FROM user_groups g LEFT JOIN application_groups ag ON ag.group_id=g.id AND ag.application_id=? ORDER BY g.name', [$appId]);
$sysRoles = $db->all('SELECT r.*,ar.role_id AS selected FROM system_roles r LEFT JOIN application_system_roles ar ON ar.role_id=r.id AND ar.application_id=? ORDER BY r.name', [$appId]);
$issuer = rtrim((string)$config['issuer'], '/');
$secret = $_SESSION['client_secrets'][$appId] ?? null;
$typeLabels = ['website'=>'Strona WWW','wordpress'=>'WordPress','php'=>'Własna aplikacja PHP','spa'=>'SPA','mobile'=>'Aplikacja mobilna','oidc'=>'Generic OpenID Connect','m2m'=>'Machine-to-Machine'];

$secretHtml = $app['client_type'] === 'public'
    ? '<span class="muted">Public Client — brak sekretu</span>'
    : (is_string($secret) && $secret !== '' ? '<code class="secret">'.Web::e($secret).'</code>' : '<span class="muted">Sekret jest przechowywany wyłącznie jako hash. Regeneruj, aby otrzymać nowy.</span>');

$rows = [
    'Issuer URL'=>$issuer,
    'Client ID'=>$app['client_id'],
    'Discovery URL'=>$issuer.'/.well-known/openid-configuration',
    'Authorization Endpoint'=>$issuer.'/oauth/authorize',
    'Token Endpoint'=>$issuer.'/oauth/token',
    'UserInfo Endpoint'=>$issuer.'/oauth/userinfo',
    'Logout Endpoint'=>$issuer.'/oauth/logout',
    'Scopes'=>implode(' ', $scopes),
    'Redirect URI'=>$redirects === [] ? 'Nie dotyczy' : implode("\n", $redirects),
];
$configRows = '<div class="kv"><span>Client Secret</span><div>'.$secretHtml.'</div></div>';
foreach ($rows as $label=>$value) $configRows .= '<div class="kv"><span>'.Web::e($label).'</span><div><code>'.nl2br(Web::e($value)).'</code></div></div>';

$groupChecks='';
foreach($groups as $g) $groupChecks .= '<label class="check"><input type="checkbox" name="group_ids[]" value="'.(int)$g['id'].'" '.($g['selected']?'checked':'').'> '.Web::e($g['name']).'</label>';
$sysRoleChecks='';
foreach($sysRoles as $r) $sysRoleChecks .= '<label class="check"><input type="checkbox" name="system_role_ids[]" value="'.(int)$r['id'].'" '.($r['selected']?'checked':'').'> '.Web::e($r['name']).'</label>';
$roleList='';
foreach($roles as $r) $roleList .= '<li><strong>'.Web::e($r['name']).'</strong>'.($r['description']?' — '.Web::e($r['description']):'').'</li>';
if($roleList==='') $roleList='<li class="muted">Brak ról aplikacyjnych.</li>';

$policyLabels=['none'=>'Brak dostępu','all'=>'Wszyscy użytkownicy','users'=>'Wybrani użytkownicy','groups'=>'Wybrane grupy','roles'=>'Wybrane role','mixed'=>'Reguły mieszane'];
$policyOptions=''; foreach($policyLabels as $value=>$label) $policyOptions.='<option value="'.$value.'" '.($app['access_policy']===$value?'selected':'').'>'.Web::e($label).'</option>';

$content='<div class="page-head"><div><h1>'.Web::e($app['name']).'</h1><p>'.Web::e($typeLabels[$app['app_type']] ?? $app['app_type']).' · '.Web::e($app['url']).'</p></div><div class="actions"><span class="badge '.((bool)$app['enabled']?'ok':'muted').'">'.((bool)$app['enabled']?'Aktywna':'Wyłączona').'</span><a class="button" href="/admin/applications/'.$appId.'/edit">Edytuj</a></div></div>';
$content.='<div class="tabs"><a href="#config">Konfiguracja</a><a href="/admin/applications/'.$appId.'/users">Użytkownicy</a><a href="#roles">Role</a><a href="#access">Dostęp</a><a href="/admin/applications/'.$appId.'/test">Testuj</a></div>';
$content.='<section class="card" id="config"><h2>Konfiguracja OIDC</h2>'.$configRows.'<div class="actions"><a class="button primary" href="/admin/applications/'.$appId.'/config.json">Pobierz konfigurację</a><a class="button" href="/admin/applications/'.$appId.'/test">Testuj integrację</a>';
if($app['client_type']==='confidential') $content.='<form method="post" action="/admin/applications/'.$appId.'/secret/regenerate" class="inline" onsubmit="return confirm(\'Regeneracja sekretu unieważni aktywne tokeny aplikacji. Kontynuować?\')"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button>Regeneruj secret</button></form>';
$content.='</div></section>';

if($app['app_type']==='wordpress') {
    $content.='<section class="card"><h2>Konfiguracja WordPress</h2><div class="kv"><span>Issuer URL</span><code>'.Web::e($issuer).'</code></div><div class="kv"><span>Client ID</span><code>'.Web::e($app['client_id']).'</code></div><div class="kv"><span>Client Secret</span><div>'.$secretHtml.'</div></div><div class="kv"><span>Scopes</span><code>openid profile email roles</code></div><p>Ustaw kompatybilny plugin OpenID Connect jako klienta OIDC. Wprowadź Discovery URL i dokładny Redirect URI zgłoszony przez plugin.</p></section>';
}

$content.='<section class="card" id="roles"><div class="page-head"><div><h2>Role aplikacyjne</h2><p>Role są niezależne dla każdej aplikacji i trafiają do claimu <code>roles</code>.</p></div></div><ul>'.$roleList.'</ul><form method="post" action="/admin/applications/'.$appId.'/roles"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><div class="form-row"><label>Nazwa roli<input name="name" placeholder="editor" required pattern="[A-Za-z0-9._-]+"></label><label>Opis<input name="description"></label></div><button class="primary">Dodaj rolę</button></form></section>';

$content.='<section class="card" id="access"><h2>Polityka dostępu</h2><form method="post" action="/admin/applications/'.$appId.'/access-policy"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Tryb<select name="access_policy">'.$policyOptions.'</select></label><div class="alert warning">Jawna blokada użytkownika ma pierwszeństwo nad dostępem z grupy, roli i polityki „wszyscy”.</div><h3>Grupy</h3><div class="checks">'.($groupChecks ?: '<span class="muted">Brak grup.</span>').'</div><h3>Role systemowe</h3><div class="checks">'.($sysRoleChecks ?: '<span class="muted">Brak ról systemowych.</span>').'</div><button class="primary">Zapisz politykę</button></form></section>';

$content.='<section class="card danger-zone"><h2>Stan aplikacji</h2><div class="actions"><form method="post" action="/admin/applications/'.$appId.'/status"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="enabled" value="'.((bool)$app['enabled']?'0':'1').'"><button>'.((bool)$app['enabled']?'Wyłącz aplikację':'Włącz aplikację').'</button></form><form method="post" action="/admin/applications/'.$appId.'/delete" onsubmit="return confirm(\'Usunąć aplikację? Tokeny zostaną unieważnione, a Audit Log pozostanie.\')"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button class="danger">Usuń aplikację</button></form></div></section>';

Web::page((string)$app['name'], $content, $admin);
