# Gorape RP passkeys and attestation

In production, Gorape must use a WebAuthn RP ID distinct from Keycloak. A
Keycloak passkey cannot be presented as a Gorape credential when their RP IDs
differ. After OIDC sign-in, the client performs a separate Gorape registration
ceremony and later uses the passkey for device possession proofs. Device
registration and proof additionally require a signed Keycloak access token
whose `amr` claim contains `passkey`; password-only login remains read-only for
device operations.

The local Docker configuration uses `gorapeflutter.site` as the Gorape RP ID,
separate from Keycloak's `idp.gorapeflutter.site` (`*.gorapeflutter.site`
resolves to `127.0.0.1` in local development). For Android Credential Manager
and Apple Associated Domains, the public association files are served from
`https://gorapeflutter.site/.well-known/assetlinks.json` and
`https://gorapeflutter.site/.well-known/apple-app-site-association`. The API
itself runs on `https://api.gorapeflutter.site:8443` (or `http://api.gorapeflutter.site:8000`);
Android Credential Manager and Apple AuthenticationServices validate the RP
domain and app association separately. Production deployments can substitute
any custom domain in `etc/server.yaml` and must configure production signing
fingerprints and trusted attestation roots.

> **Deployment caveat:** the apex `gorapeflutter.site` currently has no public
> A/AAAA record (only NS/SOA). External retrieval of the apex `/.well-known/`
> association files by Google/Apple, and public TLS issuance, are therefore
> unverified until DNS control is available. Local development uses the
> `*.gorapeflutter.site -> 127.0.0.1` records and an explicit local CA; TLS
> certificate verification must never be disabled as a workaround.

## Ceremony

1. The authenticated client requests creation options. Gorape creates a
   single-use challenge and binds it to project, principal, platform, device
   name, and WebAuthn session data in Redis.
2. The client passes the returned `public_key` options to its OS/browser
   credential provider and forwards the complete `PublicKeyCredential`
   response, including `clientDataJSON` and `attestationObject`.
3. Gorape verifies the challenge, ceremony type, configured RP ID ([GF-10010](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L99), [GF-10011](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L816)), exact allowed
   origin, credential ID, credential public key, format-specific attestation
   statement, and trust chain before storing the device ([GF-10013](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/repository/webauthn.go#L350), [GF-10017](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L152)).
4. For proof, Gorape issues a new single-use WebAuthn request challenge. The
   provider signs it; Gorape validates the assertion and updates authenticator
   counter/backup state.

The private credential key remains in the authenticator/provider. The server
stores the credential ID, COSE public key, and WebAuthn credential state. The
raw registration attestation object and certificate chain are not retained in
the credential record after verification.

The recorded `security_level` names the verified attestation format (for
example, `tpm_attested` or `apple_anonymous_attestation`); it is not a claim
about boot integrity, device uniqueness, revocation status, or ongoing
compliance.

Apply `migrations/000003_webauthn.up.sql` and
`migrations/000004_assurance.up.sql` to every existing database before
deploying the new server binary. They add nullable WebAuthn credential state,
persisted assurance evidence, and allow the `web` and `linux` device platforms;
legacy device rows remain valid and are evaluated conservatively.

## Assurance levels and policy

The assurance level is derived only from verified server-side evidence. The
client-supplied platform label is never used to promote a credential. The RP
stores the verification status and the assurance status separately, so a
successful `fmt=none` registration is `device_bound_unattested`, not
`hardware_attested`.

| Level | Verified registration | BE flag | Hardware attestation |
| --- | --- | --- | --- |
| `hardware_attested` | required | `BE=false` | required |
| `device_bound_unattested` | required | `BE=false` | not required |
| `standard_passkey` | required | `BE=true` (synchronizable) | ignored |
| `rejected` | failed or unusable | any | any |

`BE` is backup eligibility and is immutable for a credential. `BS` is backup
state and may change; `BE=false` with `BS=true`, or a change to `BE` after
registration, is rejected. A synchronizable credential is always
`standard_passkey`, even when the authenticator also supplies a hardware
attestation statement, because the key can leave the original device.

Hardware protection is accepted only when the verified evidence establishes
non-exportable key residency:

* `android-key` with a verified TEE/StrongBox key description and locked,
  verified boot;
* `apple` anonymous attestation chained to the configured Apple roots;
* `tpm` attestation chained to the configured TPM roots;
* `fido-u2f` attestation chained to the configured U2F roots;
* a FIDO MDS entry whose `keyProtection` includes `hardware`, `tee`,
  `secure_element`, or `smart_card`.

`packed` and self attestation do not by themselves prove hardware key
protection. They remain `device_bound_unattested` unless another verified
source (for example an MDS entry) adds hardware evidence. `fido_mds_verified`
likewise records metadata verification; it does not imply hardware protection.

The explicit policy controls registration and every later assertion:

```yaml
attestation:
  webauthn:
    assurance:
      required: standard_passkey      # or device_bound_unattested / hardware_attested
      allow_synced_passkeys: true     # false for high assurance
      hardware_formats: [android-key, apple, tpm, fido-u2f]
```

`required: hardware_attested` requires `allow_synced_passkeys: false` and at
least one hardware-capable format or FIDO MDS; this is validated at startup.
External proof requests may raise the requirement with `required_assurance`,
but cannot lower the service policy. The same level names are returned by
registration and proof verification.

## Cross-device authentication (CDA)

CDA is an authenticator capability, not an RP policy. Gorape records the
transports returned by the authenticator during registration and passes them
back unchanged. It does not inject `hybrid` or `internal` into
`allowCredentials`: an authenticator that did not advertise `hybrid` cannot be
made CDA-capable by a hint. When the credential record has no transports, the
RP omits the hint and lets the client choose. Device-bound keys generated by
gf-app in the OS keystore (Apple Secure Enclave, Android Keystore, Windows
CNG/TPM) are separate from WebAuthn credentials and are never substituted for a
CDA assertion; CDA uses the FIDO credential held by the authenticator.

## Metadata and revocation re-evaluation

For MDS-backed credentials Gorape re-evaluates the stored AAGUID against the
current signed metadata on assertion. A missing entry or an unacceptable
authenticator status downgrades the credential to `rejected`. When an
attestation certificate was retained and a revocation checker is configured,
the leaf certificate is re-checked against CRL/OCSP subject to the configured
cache TTL. The result and `last_evaluated_at` are persisted. Network failures
and unknown status fail closed for high-assurance decisions.

## Default-deny policy

Passkey registration is disabled until a Gorape RP ID/origin and an attestation
policy are configured. `etc/server.yaml.example` intentionally has an empty
format allowlist, `allow_none: false`, and `allow_self_attestation: false`.
`etc/server.yaml.docker` requests `direct` attestation and rejects `fmt: none`
so Android hardware-attestation support can be tested without silently
accepting an unattested result. Unknown formats, untrusted certificate chains,
and missing trust anchors fail closed. The client's requested `direct`
conveyance is only a preference; the response's actual `fmt` is authoritative.

```yaml
Application:
  Server:
    webauthn:
      rp_id: gorapeflutter.site
      rp_display_name: Gorape
      rp_origins:
        - https://gorapeflutter.site
        - https://app.gorapeflutter.site
        # Android Credential Manager native origin, if used by this app:
        - android:apk-key-hash:BASE64URL_CERTIFICATE_HASH
      # gf-app hosts the Linux browser ceremony page; Gorape remains API-only.
      portal_origin: https://app.gorapeflutter.site
      browser_api_origin: https://api.gorapeflutter.site
      attestation_conveyance: direct
      user_verification: required
    web_origins: [https://app.gorapeflutter.site]
    attestation:
      webauthn:
        allowed_formats: [android-key, tpm, apple]
        allow_none: false
        allow_self_attestation: false
        trust_anchors:
          android-key: [/etc/gorape/android-attestation-roots.pem]
          tpm: [/etc/gorape/tpm-attestation-roots.pem]
          apple: [/etc/gorape/apple-webauthn-roots.pem]
```

The root files must contain PEM certificates. `android-key` falls back to the
legacy `android_trust_anchors` list when its WebAuthn-specific list is empty.
`packed` and `fido-u2f` can also be enabled, but they require their own trusted
roots. Packed self-attestation has no certificate chain and requires both
`packed` in `allowed_formats` and `allow_self_attestation: true`; it is recorded
as `self_attested`, not hardware-backed. `none` is controlled only by the
separate `allow_none` flag.

Gorape currently validates the WebAuthn TPM 2.0 statement, including its
credential-key binding and AIK certificate properties, using
`github.com/go-webauthn/webauthn` v0.14.0, then chains the supplied certificates
to the configured format-specific roots. Root allowlisting does not perform
CRL/OCSP checks or a FIDO Metadata Service status check; keep trust bundles
current and account for revocation operationally.

## RP domain association and platform behavior

The RP ID must be stable and must match the app's platform association:

| Platform | Association / returned evidence |
| --- | --- |
| Android | Serve Digital Asset Links with `delegate_permission/common.get_login_creds` and `delegate_permission/common.handle_all_urls` at `https://<rp-id>/.well-known/assetlinks.json` for the package/signing certificate. Credential Manager may return `android-key` or `none`. |
| iOS/macOS | Serve AASA `webcredentials` entries and build with `webcredentials:<rp-id>` Associated Domains. AuthenticationServices controls platform attestation conveyance; the response may be Apple anonymous attestation or `none`. |
| Windows | Uses the Windows WebAuthn API. A TPM `tpm` statement is provider/OS dependent and is not guaranteed by requesting `direct`. |
| Web | Must be served in a secure context; RP ID must be the page host or a registrable parent domain. Browser/provider policy may anonymize attestation to `none`. |
| Linux | The gf-app web target opens the browser ceremony page. Chrome/Firefox WebAuthn uses its configured platform or roaming authenticator. Gorape remains API-only. |

Every browser or native origin must be configured exactly in `rp_origins`.
HTTPS origins must be within the RP ID; HTTP is accepted only for localhost
development. Android's `android:apk-key-hash:` native origin is an explicit
exact-match exception. Never configure wildcard origins.
`portal_origin` must be both the gf-app ceremony page origin and a member of
`rp_origins`; `browser_api_origin` is the public Gorape API origin used by the
cross-origin browser handoff and must be reachable from that page. Add the
portal origin to `web_origins` for exact CORS authorization. The fragment
contains a short-lived challenge ID (never the OIDC token), and the browser
submits the response to one-time capability endpoints.

Attestation does not prove OS boot integrity or ongoing device compliance.
Provider behavior varies by OS version, account configuration, authenticator,
and whether credentials are synced. The platform label sent by the client is
metadata only; authorization and attestation assurance come from the verified
WebAuthn response and server policy.

## RP ID migration and credential re-enrollment

WebAuthn credentials are cryptographically bound to their RP ID (`rpIdHash = SHA-256(rpId)` in `authenticatorData`). Changing `Application.Server.WebAuthn.rp_id` (for example from `gorapeflutter.github.io` or `localhost` to `gorapeflutter.site`, or from `gorapeflutter.site` to a custom production domain) makes previously enrolled WebAuthn credentials unusable under the new RP ID.

When migrating RP IDs:
1. Update `Application.Server.WebAuthn.rp_id`, `rp_origins`, `portal_origin`, `browser_api_origin`, and `web_origins` in `etc/server.yaml` (or `etc/server.yaml.docker`).
2. Publish the updated `/.well-known/assetlinks.json` and `/.well-known/apple-app-site-association` on `https://<new-rp-id>/.well-known/`.
3. Update the native app's Android `asset_statements` and Apple `com.apple.developer.associated-domains` (`webcredentials:<new-rp-id>`).
4. Revoke existing devices bound to the old RP ID via `DELETE /v1/projects/{projectId}/devices/{deviceId}` and re-enroll each device under the new RP ID via `POST /v1/projects/{projectId}/devices/passkeys/registration/options` and `/verify` ([GF-10016](https://github.com/Gorapeflutter/gorape/blob/main/pkg/server/usecase/passkey_device.go#L92).
