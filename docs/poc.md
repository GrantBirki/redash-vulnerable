# POC

✅ CVE-2021-21239 vulnerability is present - Redash is using pysaml2 6.1.0 which is vulnerable
✅ xmlsec1 is available - Version 1.2.27 (openssl)
✅ Our self-signed certificate is being accepted - The logs show the certificate verification warning but not rejection
✅ CVE-2021-21239 is triggered - xmlsec1 is using our embedded certificate instead of the configured one
❌ Signature verification fails - Our digest calculation or signature generation is not matching xmlsec1's expectations

---

```console
$ docker compose exec redash bash -c "python3 -c \"
> import saml2
> print('pysaml2 version:', saml2.__version__)
> 
> import subprocess
> result = subprocess.run(['which', 'xmlsec1'], capture_output=True, text=True)
> if result.returncode == 0:
>     print('xmlsec1 path:', result.stdout.strip())
> else:
>     print('xmlsec1 not found')
> \""
pysaml2 version: 6.1.0
xmlsec1 path: /usr/bin/xmlsec1
birki@birkis-MacBook-Pro ~/code/redash-vulnerable (main)
$ docker compose exec redash xmlsec1 --version
xmlsec1 1.2.27 (openssl)
```
