# redash-vulnerable 🐛

A Dockerized Redash instance that is vulnerable to [`CVE-2021-21239`](https://nvd.nist.gov/vuln/detail/CVE-2021-21239) as written about by [Calif](https://blog.calif.io/p/redash-saml-authentication-bypass).

## Usage 💻

### Starting the server (preserving data)

```bash
script/server
```

This will start the Redash server using Docker Compose in detached mode, preserving any existing data. The server will be available at [`http://localhost:8080`](http://localhost:8080/setup).

### Starting fresh (destroying all data)

```bash
script/server --destroy
```

This will destroy all existing containers, volumes, and data directories, then rebuild everything from scratch. Use this when you want to start completely fresh.

**Note:** The `--destroy` flag will permanently delete all your Redash data, including dashboards, queries, users, and database content.
