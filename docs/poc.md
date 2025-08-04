# POC

✅ CVE-2021-21239 vulnerability is present - Redash is using pysaml2 6.1.0 which is vulnerable
✅ xmlsec1 is available - Version 1.2.27 (openssl)
✅ Our self-signed certificate is being accepted - The logs show the certificate verification warning but not rejection
✅ CVE-2021-21239 is triggered - xmlsec1 is using our embedded certificate instead of the configured one
❌ Signature verification fails - Our digest calculation or signature generation is not matching xmlsec1's expectations
