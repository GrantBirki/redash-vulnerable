# redash-vulnerable 🐛

A Dockerized Redash instance that is vulnerable to [`CVE-2021-21239`](https://nvd.nist.gov/vuln/detail/CVE-2021-21239) as written about by [Calif](https://blog.calif.io/p/redash-saml-authentication-bypass).

## Usage 💻

```bash
script/server
```

This will run and start the redash server using Docker Compose in a detached mode. The server will be available at [`http://localhost:8080`](http://localhost:8080/setup).

Running the `script/server` command again will destroy the existing instance and fully rebuild/start a new server from scratch.
