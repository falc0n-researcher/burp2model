# Exporting from Burp Suite

Burp Community Edition is enough.

1. Set **Target > Scope** and browse the app through Burp's proxy as the role you want to capture.
2. Open **Proxy > HTTP history** (or **Target > Site map**).
3. Select all rows (`Ctrl+A` / `Cmd+A`).
4. Right-click, then **Save items**.
5. Keep "base64-encode requests and responses" checked (the default).

Then run:

```bash
burp2model history.xml --webapp shop
```

## Two roles

Export once per role, then compare:

```bash
burp2model user.xml  -w shop --role user  --out o
burp2model admin.xml -w shop --role admin --out o
burp2model cross-role shop --low user --high admin --out o
```

Rebuilding a role replaces only that role. A build without `--role`, or with `--fresh`, starts over. Capture a logged-out session as its own role, for example `--role anonymous`.

## Logger++ CSV

```bash
burp2model logs.csv -w app --role user --skip-tools Scanner
```

The CSV needs `Method`, `Host`, `Request` and `Response` columns (base64 or raw HTTP). Use `--skip-tools` or `--only-tools` to filter by the `Tool` column. Rows split by a spreadsheet at 32,767 characters are rejoined; a response that stays cut off is flagged.

## Without Burp

`burp2model crawl https://your.app/ --yes` builds the model from a running app. See [CRAWLING.md](CRAWLING.md).

Only capture traffic you are authorized to record. Everything runs locally.
