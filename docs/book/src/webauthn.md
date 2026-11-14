# Gorape RP passkeys and attestation

In production, Gorape must use a WebAuthn RP ID distinct from Keycloak. A
Keycloak passkey cannot be presented as a Gorape credential when their RP IDs
differ. After OIDC sign-in, the client performs a separate Gorape registration
ceremony and later uses the passkey for device possession proofs. Device
registration and proof additionally require a signed Keycloak access token
whose `amr` claim contains `passkey`; password-only login remains read-only for
device operations.

The local Docker configuration uses `gorapeflutter.github.io` as the Gorape RP
ID, separate from Keycloak's `localhost`. The organization Pages repository
publishes the Android Digital Asset Links statement at
`https://gorapeflutter.github.io/.well-known/assetlinks.json`. The API itself
can remain on a local HTTPS endpoint; Android Credential Manager validates the
RP domain and app association separately. This setup uses the current debug
signing certificate and is for development only. Production must configure
production signing fingerprints and trusted attestation roots.

## Ceremony

1. The authenticated client requests creation options. Gorape creates a
   single-use challenge and binds it to project, principal, platform, device
   name, and WebAuthn session data in Redis.
2. The client passes the returned `public_key` options to its OS/browser
   credential provider and forwards the complete `PublicKeyCredential`
   response, including `clientDataJSON` and `attestationObject`.
3. Gorape verifies the challenge, ceremony type, configured RP ID, exact allowed
   origin, credential ID, credential public key, format-specific attestation
   statement, and trust chain before storing the device.
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

Apply `migrations/000003_webauthn.up.sql` to every existing database before
deploying the new server binary. It adds nullable WebAuthn credential state and
allows the `web` and `linux` device platforms; legacy device rows remain valid.

## Default-deny policy

Passkey registration is disabled until a Gorape RP ID/origin and an attestation
policy are configured. `etc/server.yaml.example` intentionally has an empty
format allowlist, `allow_none: false`, and `allow_self_attestation: false`.
`etc/server.yaml.docker` is a local-only exception: it allows `fmt: none` for
the Android debug ceremony, while the production example remains default-deny.
Unknown formats, untrusted certificate chains, and missing trust anchors fail
closed. The client's requested `direct` conveyance is only a preference; the
response's actual `fmt` is authoritative.

```yaml
Application:
  Server:
    webauthn:
      rp_id: gorape.example.com
      rp_display_name: Gorape
      rp_origins:
        - https://app.gorape.example.com
        # Android Credential Manager native origin, if used by this app:
        - android:apk-key-hash:BASE64URL_CERTIFICATE_HASH
      # gf-app hosts the Linux browser ceremony page; Gorape remains API-only.
      portal_origin: https://app.gorape.example.com
      browser_api_origin: https://api.gorape.example.com
      attestation_conveyance: direct
      user_verification: required
    web_origins: [https://app.gorape.example.com]
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
