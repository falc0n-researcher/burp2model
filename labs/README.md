# Labs

Local test apps for burp2model. Bind them to localhost only. Results: [`docs/TESTED_APPS.md`](../docs/TESTED_APPS.md).

```bash
docker run --rm -d -p 127.0.0.1:8081:80    vulnerables/web-dvwa      # open /setup.php, create the database
docker run --rm -d -p 127.0.0.1:3000:3000  bkimminich/juice-shop
(cd labs/react-shop && npm install && npm start)                     # http://127.0.0.1:3100

burp2model crawl http://127.0.0.1:8081/ -w dvwa --role anon --yes
DVWA_USER=admin DVWA_PASS=password burp2model crawl http://127.0.0.1:8081/ -w dvwa \
  --role admin --yes --journey samples/journeys/dvwa-login.json
```

Mutillidae (`citizenstig/nowasp`) and WebGoat (`webgoat/webgoat`) also have journeys in `samples/journeys/`.
The React shop users are `alice@shop.test` / `Passw0rd!` (user) and `root@shop.test` / `Adm1nPass!` (admin).
Its true API table is in `server.js`, so a crawl can be scored against it.
