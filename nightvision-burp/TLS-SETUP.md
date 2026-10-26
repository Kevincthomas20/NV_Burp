# API TLS connection recovery — version 0.4.1

If browser SSO completes but Burp reports `SSLHandshakeException`, the failure
is occurring in the extension's Java HTTPS connection to NightVision. The
browser, CLI, and Burp's Java runtime can have different trusted certificate
stores. The new diagnostics distinguish an untrusted chain from hostname,
certificate-date, and TLS negotiation failures.

## Update and reconnect

1. Unload the previous extension and load
   `nightvision-burp/dist/nightvision-burp-0.4.1.jar` from this ZIP.
2. Keep the normal NightVision API origin. Because you already completed
   browser login, click **Use saved login**.
3. On Windows, leave **Use trusted Windows roots** selected. The API client
   retains JVM trust and also tries the native current-user and machine ROOT
   stores when supported by your running JVM.
4. If a certificate-chain error remains and your workplace uses a company
   issuer/TLS inspection CA, obtain the corresponding CA certificate from your
   IT team. Click **Browse CA** beside **Additional trusted CA (optional)**,
   select that PEM/DER certificate file (`.pem`, `.cer`, or `.crt`), then click
   **Use saved login** again.

The file must contain valid issuer/root CA certificates, rather than the
server's leaf certificate. The extension accepts 1–32 CA certificates in a
file up to 2 MiB, checks their validity dates, and remembers the file path.
On Linux/macOS, the additional-CA option supplies the same API-scoped trust
without requiring native Windows stores.

## Read the diagnostic result

Open **Connection diagnostics** after the failing action:

| Result | Next step |
| --- | --- |
| Cannot validate certificate chain / PKIX | Check Windows-store availability or select the correct IT-provided issuer CA, then reconnect. |
| Certificate hostname mismatch | Check the API origin and the certificate presented by the server or network gateway. A trusted issuer does not override a hostname mismatch. |
| Certificate outside validity dates | Check the machine's date/time and have the server or gateway certificate checked. |
| TLS negotiation failure | Check the Burp/Java version and network gateway's TLS configuration. |
| Cannot read or initialize selected CA | Check the path, PEM/DER format, and that the file contains currently valid CA certificates. |

Diagnostics show Java version/home, the configured JVM trust-store location,
requested Windows trust, and cause types. A TLS failure after trust setup also
reports which Windows stores loaded and selected-CA SHA-256 fingerprints.
Credentials, trust-store passwords, raw process output, and raw exception
messages are omitted. Share this diagnostic text if the connection still
fails; do not share the saved-login config or token.

## Scope and persistence

The trust settings apply to this extension's API clients only. They do not
edit JVM or Windows trust stores, change your browser/CLI, or change Repeater.
Certificate-chain validation and HTTPS hostname checks stay enabled. JVM roots
remain available when additional roots are selected. If a Windows store is
unavailable to the running JVM, the failure diagnostic records that fact and
the optional CA file remains available.

The CA file path and Windows-roots checkbox preference are saved in Burp
preferences. Changing them takes effect when you reconnect. Clear the CA path
and reconnect to stop using that additional file.

## Validation

The build passed **275 checks**, including real local HTTPS tests that reject
untrusted chains before any authenticated request, accept the selected test
CA, reject the wrong hostname, and keep that trust isolated from global JVM
settings. Tests generate temporary certificates/private keys locally and
remove them afterward; no keys are packaged. Native Windows stores and your
company's live TLS gateway still need testing in your environment.
