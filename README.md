# dir_loot.py

Automated secret scanner for browsable web directories. Takes Nessus output (or a plain URL list), recursively crawls every directory listing, downloads files, and scans them for credentials, API keys, private keys, and other sensitive data.

Built for external network penetration tests where Nessus dumps hundreds of browsable directories and you need to triage them fast.

## What It Does

1. **Parses input** -- reads `.nessus` XML, Nessus CSV exports, or a plain text file of URLs
2. **Crawls recursively** -- follows directory listing links (Apache, Nginx, IIS, etc.) down to configurable depth
3. **Downloads and scans** -- pulls files under a size limit, runs 30+ regex patterns for secrets, flags sensitive filenames
4. **Reports findings** -- outputs a text report (sorted by severity, grouped by host), a JSON file for scripting, and a full file inventory CSV

All requests are GET-only. Nothing destructive.

## Requirements

- Python 3.8+
- `requests` (`pip3 install requests`)

Pre-installed on Kali. No other dependencies.

## Usage

```bash
# From a Nessus export
python3 dir_loot.py -i scan.nessus -o ./loot

# From a plain URL list (one per line)
python3 dir_loot.py -i urls.txt -o ./loot

# From a Nessus CSV export
python3 dir_loot.py -i export.csv -o ./loot

# Crank up threads and crawl depth
python3 dir_loot.py -i scan.nessus -o ./loot -t 30 -d 15

# Route through Burp
python3 dir_loot.py -i scan.nessus -o ./loot --proxy http://127.0.0.1:8080

# Just inventory files without downloading
python3 dir_loot.py -i scan.nessus -o ./loot --crawl-only
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | *(required)* | Input file: `.nessus`, `.csv`, or text URL list |
| `-o, --output` | `./loot` | Output directory |
| `-t, --threads` | `20` | Concurrent threads |
| `-d, --depth` | `10` | Max recursive crawl depth |
| `--timeout` | `15` | Per-request timeout (seconds) |
| `--max-size` | `10485760` | Max file download size in bytes (10 MB) |
| `--proxy` | | HTTP proxy (e.g., `http://127.0.0.1:8080`) |
| `--user-agent` | Chrome 125 | Custom User-Agent string |
| `--cookie` | | Cookie as `name=value` (repeatable) |
| `--auth` | | Basic auth as `user:pass` |
| `--crawl-only` | | Crawl and inventory only, skip downloads |

## Input Formats

**Nessus XML (.nessus)** -- Parses plugin output from directory listing plugins (11032, 40984, and anything with "browsable" or "directory listing" in the plugin name). Export your scan as `.nessus` from the Nessus UI.

**Nessus CSV** -- Works with standard Nessus CSV exports. Looks for `Plugin ID` and `Plugin Output` columns.

**Plain text** -- One URL per line. Lines starting with `#` are ignored.

```
# target directories
http://198.51.100.10/backup/
http://198.51.100.10:8080/files/
https://webapp.example.com/assets/
```

## Output

Everything lands in the output directory (`./loot` by default):

```
loot/
  findings.txt          # Human-readable report sorted by severity
  findings.json         # Machine-readable findings for scripting
  file_inventory.csv    # Every file URL discovered during crawl
  downloads/            # Downloaded files, organized by host
    198.51.100.10/
      backup/
        db_dump.sql
        config.php.bak
    webapp.example.com/
      assets/
        .env
```

### findings.txt

The text report includes:
- Summary stats (directories crawled, files found, secrets, interesting files)
- Per-host finding counts
- Secret findings with severity, matched pattern, URL, line number, and surrounding context
- Interesting file listings with reasons (sensitive filename, backup extension, source control artifact, etc.)

### findings.json

Array of finding objects for further processing:

```json
{
  "type": "secret",
  "pattern_name": "AWS Access Key ID",
  "severity": "CRITICAL",
  "url": "http://198.51.100.10/backup/config.js",
  "match": "AKIAIOSFODNN7EXAMPLE",
  "context": "var accessKey = \"AKIAIOSFODNN7EXAMPLE\";",
  "line": 42,
  "local_path": "./loot/downloads/198.51.100.10/backup/config.js"
}
```

## What It Detects

### Secrets (30+ patterns)

- AWS access keys and secret keys
- Google API keys and OAuth client IDs
- Azure storage account keys
- Private keys (RSA, DSA, EC, OpenSSH, PGP)
- GitHub, GitLab, Slack, Discord, Stripe, SendGrid, Twilio, Mailgun, Square, NPM, Dynatrace, HashiCorp Vault, and Heroku tokens
- Database connection strings (MySQL, PostgreSQL, MongoDB, MSSQL, Redis, AMQP)
- JDBC connection strings
- Basic auth credentials embedded in URLs
- JWT tokens
- Password/secret/token assignments in config files
- Environment variable secrets (DB_PASSWORD, SECRET_KEY, etc.)
- `.htpasswd` and shadow file entries

### Interesting Files (flagged by name or extension)

- Environment files: `.env`, `.env.production`, `.env.bak`, etc.
- Config files: `wp-config.php`, `web.config`, `database.yml`, `appsettings.json`, etc.
- Key material: `.pem`, `.key`, `.p12`, `.pfx`, `.jks`
- Backups: `.bak`, `.backup`, `.old`, `.orig`, `.sql`, `.sqlite`
- Auth files: `.htpasswd`, `.pgpass`, `.netrc`
- Source control: `.git/config`, `.svn/entries`
- Infrastructure: `Dockerfile`, `docker-compose.yml`, `terraform.tfvars`, `terraform.tfstate`
- Server config: `tomcat-users.xml`, `server.xml`, `phpinfo.php`

### Skipped (not downloaded)

Images, video, audio, fonts, compiled binaries, and bytecode files are skipped to save bandwidth. They are still listed in the file inventory CSV.

## Tips

- **Start with `--crawl-only`** to see what's out there before committing to a full download. Review `file_inventory.csv` and adjust scope if needed.
- **Route through Burp** with `--proxy` to capture all traffic in your project file for evidence.
- **Pipe findings into other tools** -- `findings.json` is structured for `jq`, custom scripts, or import into reporting tools.
- **Adjust `--max-size`** if you're seeing large files you want to pull (database dumps, log files). Default is 10 MB.
- **Ctrl+C is safe** -- partial results are preserved in the output directory.

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Only use it against systems you have explicit written permission to test. Unauthorized access to computer systems is illegal.
