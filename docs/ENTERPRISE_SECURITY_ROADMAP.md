# Enterprise security roadmap

This branch starts the enterprise/security expansion requested for imAuthenticator.

## Implemented foundation in this iteration

- Organizations / tenants and organization memberships.
- Delegated application administrators and application owners.
- Account lifecycle, start/end dates and activity timestamps.
- Temporary grants and automatic access expiry fields.
- Self-service access requests and approval decisions.
- Dynamic access/ABAC rule storage and application conditional-access policy storage.
- Per-application and per-system-role MFA policy model.
- WebAuthn/passkey credential and challenge storage.
- MFA methods and backup codes model.
- Trusted-device/device-management and login-risk event storage.
- External IdP model for OIDC, SAML, Entra ID, Google, GitHub, LDAP and Active Directory.
- LDAP/AD sync run history and external identity linking.
- SAML service-provider settings and SCIM connector model.
- Client-secret rotation/expiration model and signing-key history/Vault/KMS/HSM references.
- Service accounts / API keys.
- Per-client claims mapping/privacy model.
- Access reviews.
- Application categories/favorites/order/status metadata.
- Webhook event outbox and SIEM/syslog integration configuration.
- Terms/Privacy versions, acceptance history and required actions.
- Hash-chain fields for tamper-evident audit logging.

## Next implementation layers

1. ApplicationAccessService enforcement for temporal grants, account lifecycle and dynamic rules.
2. ConditionalAccessService with MFA, trusted device, IP/network/geo/time/risk/session checks.
3. AccessRequestService and admin/user UI for request/approve/deny with expiry.
4. Passkey registration/login using `web-auth/webauthn-lib` with browser WebAuthn API.
5. SAML 2.0 IdP endpoints using a maintained SAML toolkit.
6. LDAP/AD connection test and scheduled synchronization worker.
7. External OIDC/social providers (Entra ID, Google, GitHub) through a provider adapter.
8. SCIM 2.0 Users/Groups endpoints and outbound connector worker.
9. Client secret/key rotation and JWKS key history.
10. Device Flow, PAR, JAR/JARM, DPoP, mTLS and token exchange.
11. Security dashboard, immutable audit verification, export/retention and SIEM delivery.
12. Application templates and config/snippet generators.

Security questions are intentionally excluded.
