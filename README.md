# imAuthenticator

`imAuthenticator` to centralne centrum logowania i autoryzacji OAuth 2.0 / OpenID Connect napisane w PHP 8.2+ i MySQL.

Aktualna implementacja zawiera moduł zarządzania aplikacjami klienckimi, per-aplikacyjne polityki dostępu użytkowników, role aplikacyjne, Authorization Code + PKCE, refresh token rotation, UserInfo, discovery/JWKS, Machine-to-Machine oraz Audit Log.

## Instalacja

1. Ustaw katalog `public/` jako DocumentRoot serwera WWW.
2. Otwórz adres aplikacji w przeglądarce.
3. Jeżeli `config/config.php` nie istnieje, aplikacja przekieruje do `/install.php`.
4. Podaj dane MySQL, Issuer URL i konto administratora.
5. Instalator automatycznie:
   - utworzy bazę danych,
   - wykona `database/schema.sql` i migracje,
   - utworzy administratora,
   - wygeneruje parę RSA 3072 bit do podpisywania ID Tokenów,
   - zapisze lokalną konfigurację.

Nie trzeba ręcznie wykonywać SQL ani tworzyć kluczy OIDC.

Wymagania: PHP >= 8.2, PDO MySQL, OpenSSL, JSON oraz MySQL/MariaDB zgodne z użytym schematem.

## Aplikacje klienckie

Administrator przechodzi do `Aplikacje -> Dodaj aplikację`. Kreator obsługuje:

- Strona WWW,
- WordPress,
- własna aplikacja PHP,
- SPA,
- aplikacja mobilna,
- Generic OpenID Connect,
- Machine-to-Machine.

Presety integracji:

- WordPress / OpenID Connect,
- Generic OpenID Connect,
- Public Client + PKCE,
- Machine-to-Machine / Client Credentials.

`client_id` oraz `client_secret` są generowane kryptograficznie. Sekret confidential client jest przechowywany tylko jako Argon2id hash i jest prezentowany administratorowi po utworzeniu lub regeneracji.

Redirect URI są dopasowywane dokładnie. Wildcardy są odrzucane. Domyślnie wymagany jest HTTPS; HTTP jest akceptowany wyłącznie dla `localhost`, `127.0.0.1` i `::1`.

## Kontrola dostępu

Nowa aplikacja ma domyślnie politykę `Brak dostępu`.

Dostęp może wynikać z:

- jawnego przypisania użytkownika,
- wszystkich aktywnych użytkowników,
- członkostwa w wybranych grupach,
- ról systemowych,
- reguł mieszanych.

Jawna decyzja per użytkownik ma najwyższy priorytet:

- `enabled=1` w `application_users` daje użytkownikowi dostęp,
- `enabled=0` jest deny override i blokuje dostęp nawet odziedziczony przez `all`, grupę lub rolę.

Ta sama usługa `ApplicationAccessService` jest używana przez dashboard oraz backend OAuth/OIDC. Brak dostępu nie jest jedynie ukryciem ikony aplikacji.

Przed wydaniem authorization code wykonywane są kolejno kontrole klienta, aktywności aplikacji, dokładnego redirect URI, aktywności użytkownika oraz dostępu do aplikacji. Dostęp jest sprawdzany ponownie przy wymianie authorization code, użyciu refresh tokena i wywołaniu UserInfo.

Odebranie dostępu natychmiast unieważnia access tokeny, refresh tokeny i sesje OIDC dla pary użytkownik/aplikacja.

## OAuth / OpenID Connect

Endpointy:

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/userinfo`
- `/oauth/logout`

Obsługiwane flow:

- Authorization Code,
- Authorization Code + PKCE S256 dla public clients,
- Refresh Token z rotacją,
- Client Credentials dla Machine-to-Machine.

ID Tokeny są podpisywane `RS256`. Access i refresh tokeny są losowymi tokenami opaque; baza przechowuje wyłącznie ich SHA-256 hash.

## Role aplikacyjne

Każda aplikacja może posiadać własne role, np. `admin`, `editor`, `viewer`. Ten sam użytkownik może mieć inne role w każdej aplikacji.

Role aplikacyjne są zwracane w ID Token i UserInfo w claimie `roles`.

## WordPress

Dla typu WordPress panel pokazuje gotową konfigurację:

- Issuer URL,
- Client ID,
- Client Secret, jeżeli został właśnie wygenerowany,
- scopes `openid profile email roles`,
- Redirect URI,
- Discovery URL.

Konfiguracja jest zgodna z typowym klientem OpenID Connect oraz przygotowana pod przyszły plugin `imAuthenticator` dla WordPress.

## Test integracji

Administrator może uruchomić pełny test aplikacji. Test sprawdza klienta, redirect URI, sesję użytkownika, politykę dostępu, wygenerowanie authorization code, token endpoint i UserInfo. Rzeczywiste tokeny nie są zapisywane w Audit Log i są unieważniane po teście.

## Audit Log

Rejestrowane są m.in.:

- utworzenie aplikacji,
- zmiany polityki dostępu,
- nadanie i odebranie dostępu,
- operacje na rolach,
- regeneracja sekretu,
- wyłączenie i soft-delete aplikacji,
- udane logowanie SSO,
- odmowy OAuth/OIDC,
- niepoprawne uwierzytelnienie klienta.

## Bezpieczeństwo

- PDO prepared statements,
- CSRF dla operacji panelu,
- cookies `HttpOnly`, `SameSite=Lax` i `Secure` przy HTTPS,
- Argon2id dla haseł i client secrets,
- exact-match redirect URI,
- zakaz wildcard redirect URI,
- PKCE S256 dla public clients,
- jednorazowe authorization codes z krótkim TTL,
- ponowne sprawdzanie dostępu przed wydaniem/odświeżeniem tokenów,
- natychmiastowa revokacja tokenów przy odebraniu dostępu,
- soft-delete aplikacji dla zachowania audytu,
- brak tokenów i sekretów w Audit Log.

## Struktura

- `public/` — front controller, installer, endpoint token i assety,
- `src/` — baza danych, sesje, bezpieczeństwo, dostęp aplikacyjny, OIDC i audyt,
- `database/schema.sql` — główny schemat,
- `database/migrations/` — migracje wykonywane automatycznie przez instalator,
- `config/` — lokalna konfiguracja i klucze; sekrety są ignorowane przez Git.
