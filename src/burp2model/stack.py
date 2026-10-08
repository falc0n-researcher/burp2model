"""What an app is built on, read from the capture: servers, frameworks, CDNs and third-party services.

Every entry is a hint tied to the requests that showed it, never a version scan. Signatures are
deliberately few and conservative. Detection runs per response while parsing (headers, cookie names,
HTML and script markers), and third-party hosts are matched to vendors when the model is built.
"""

from __future__ import annotations

import re

# column order for the stack map
CATEGORIES = ["Edge & CDN", "Web server", "Language & framework", "Frontend", "CMS & platform",
              "API", "Services"]

# (header, regex on its value, name, category); the capture group, if any, is the version
_HEADER_SIGNS = [
    ("server", r"cloudflare", "Cloudflare", "Edge & CDN"),
    ("server", r"akamaighost|akamai", "Akamai", "Edge & CDN"),
    ("server", r"cloudfront", "Amazon CloudFront", "Edge & CDN"),
    ("server", r"\bfastly\b", "Fastly", "Edge & CDN"),
    ("server", r"netlify", "Netlify", "Edge & CDN"),
    ("server", r"vercel", "Vercel", "Edge & CDN"),
    ("server", r"sucuri", "Sucuri", "Edge & CDN"),
    ("server", r"nginx(?:/([\d.]+))?", "nginx", "Web server"),
    ("server", r"apache(?:/([\d.]+))?", "Apache", "Web server"),
    ("server", r"microsoft-iis(?:/([\d.]+))?", "IIS", "Web server"),
    ("server", r"openresty(?:/([\d.]+))?", "OpenResty", "Web server"),
    ("server", r"litespeed", "LiteSpeed", "Web server"),
    ("server", r"caddy", "Caddy", "Web server"),
    ("server", r"gunicorn(?:/([\d.]+))?", "Gunicorn", "Web server"),
    ("server", r"uvicorn", "Uvicorn", "Web server"),
    ("server", r"kestrel", "Kestrel", "Web server"),
    ("server", r"envoy", "Envoy", "Web server"),
    ("server", r"jetty(?:\(?([\d.]+))?", "Jetty", "Web server"),
    ("server", r"tomcat", "Apache Tomcat", "Web server"),
    ("server", r"\bcowboy\b", "Cowboy", "Web server"),
    ("server", r"werkzeug(?:/([\d.]+))?", "Werkzeug", "Web server"),
    ("server", r"phusion passenger", "Passenger", "Web server"),
    ("server", r"\bgws\b|\besf\b", "Google Frontend", "Edge & CDN"),
    ("server", r"amazons3", "Amazon S3", "Edge & CDN"),
    ("x-powered-by", r"php(?:/([\d.]+))?", "PHP", "Language & framework"),
    ("x-powered-by", r"express", "Express", "Language & framework"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Language & framework"),
    ("x-powered-by", r"next\.js(?: ([\d.]+))?", "Next.js", "Language & framework"),
    ("x-powered-by", r"servlet|jsp", "Java Servlet", "Language & framework"),
    ("x-powered-by", r"phusion passenger", "Passenger", "Web server"),
    ("x-powered-by", r"django", "Django", "Language & framework"),
    ("x-powered-by", r"flask", "Flask", "Language & framework"),
    ("x-powered-by", r"wp engine", "WP Engine", "CMS & platform"),
    ("x-aspnet-version", r"([\d.]+)", "ASP.NET", "Language & framework"),
    ("x-aspnetmvc-version", r"([\d.]+)", "ASP.NET MVC", "Language & framework"),
    ("x-generator", r"drupal(?: ([\d.]+))?", "Drupal", "CMS & platform"),
    ("x-generator", r"wordpress(?: ([\d.]+))?", "WordPress", "CMS & platform"),
    ("x-generator", r"joomla", "Joomla", "CMS & platform"),
    ("x-drupal-cache", r".", "Drupal", "CMS & platform"),
    ("x-shopify-stage", r".", "Shopify", "CMS & platform"),
    ("x-wix-request-id", r".", "Wix", "CMS & platform"),
    ("x-vercel-id", r".", "Vercel", "Edge & CDN"),
    ("x-nf-request-id", r".", "Netlify", "Edge & CDN"),
    ("cf-ray", r".", "Cloudflare", "Edge & CDN"),
    ("x-amz-cf-id", r".", "Amazon CloudFront", "Edge & CDN"),
    ("x-akamai-transformed", r".", "Akamai", "Edge & CDN"),
    ("x-azure-ref", r".", "Azure Front Door", "Edge & CDN"),
    ("x-fastly-request-id", r".", "Fastly", "Edge & CDN"),
    ("x-github-request-id", r".", "GitHub Pages", "Edge & CDN"),
    ("x-sucuri-id", r".", "Sucuri", "Edge & CDN"),
    ("x-served-by", r"cache-", "Fastly", "Edge & CDN"),
    ("via", r"varnish", "Varnish", "Edge & CDN"),
    ("via", r"cloudfront", "Amazon CloudFront", "Edge & CDN"),
]

# cookie name patterns -> technology
_COOKIE_SIGNS = [
    (r"^PHPSESSID$", "PHP", "Language & framework"),
    (r"^JSESSIONID$", "Java", "Language & framework"),
    (r"^ASP\.NET_SessionId$|^\.ASPXAUTH$", "ASP.NET", "Language & framework"),
    (r"^laravel_session$", "Laravel", "Language & framework"),
    (r"^csrftoken$|^django_language$", "Django", "Language & framework"),
    (r"^connect\.sid$", "Express", "Language & framework"),
    (r"^rack\.session$", "Rack", "Language & framework"),
    (r"^_rails|^_session_id$", "Ruby on Rails", "Language & framework"),
    (r"^wordpress_|^wp-settings", "WordPress", "CMS & platform"),
    (r"^_shopify_", "Shopify", "CMS & platform"),
    (r"^__cf_bm$|^cf_clearance$|^__cfduid$", "Cloudflare", "Edge & CDN"),
    (r"^AWSALB|^AWSELB", "AWS Load Balancer", "Edge & CDN"),
    (r"^BIGipServer|^TS[0-9a-f]{8}", "F5 BIG-IP", "Edge & CDN"),
    (r"^NSC_", "Citrix NetScaler", "Edge & CDN"),
    (r"^incap_ses|^visid_incap", "Imperva", "Edge & CDN"),
    (r"^ak_bmsc$|^bm_sz$", "Akamai", "Edge & CDN"),
]

# markers in HTML and script bodies -> technology (version from the first group when present)
_BODY_SIGNS = [
    (r"/_next/static/|__NEXT_DATA__", "Next.js", "Language & framework"),
    (r"window\.__NUXT__|/_nuxt/", "Nuxt", "Language & framework"),
    (r"ng-version=\"([\d.]+)\"", "Angular", "Frontend"),
    (r"<app-root|@angular/core", "Angular", "Frontend"),
    (r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom", "React", "Frontend"),
    (r"data-v-[0-9a-f]{8}|vue(?:\.runtime)?(?:\.min)?\.js|__vue__", "Vue", "Frontend"),
    (r"svelte-[a-z0-9]{5,}|__svelte", "Svelte", "Frontend"),
    (r"jquery[-.]?([\d.]+\d)?(?:\.min)?\.js", "jQuery", "Frontend"),
    (r"bootstrap[-.]?([\d.]+\d)?(?:\.bundle)?(?:\.min)?\.(?:js|css)", "Bootstrap", "Frontend"),
    (r"webpackJsonp|webpackChunk|__webpack_require__", "Webpack", "Frontend"),
    (r"/@vite/client|vite/modulepreload", "Vite", "Frontend"),
    (r"wp-content/|wp-includes/", "WordPress", "CMS & platform"),
    (r"/sites/default/files|Drupal\.settings", "Drupal", "CMS & platform"),
    (r"cdn\.shopify\.com", "Shopify", "CMS & platform"),
    (r"static\.parastorage\.com|wixstatic\.com", "Wix", "CMS & platform"),
    (r"static1\.squarespace\.com", "Squarespace", "CMS & platform"),
    (r"assets\.website-files\.com|webflow\.js", "Webflow", "CMS & platform"),
    (r"socket\.io", "Socket.IO", "API"),
]

_GENERATOR = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.I)
_PATH_SIGNS = [
    (r"/graphql\b", "GraphQL", "API"),
    (r"/socket\.io/", "Socket.IO", "API"),
    (r"/signalr\b", "SignalR", "API"),
]

# third-party hosts (suffix match) -> (vendor, kind)
_VENDORS = [
    ("google-analytics.com", "Google Analytics", "Analytics"), ("googletagmanager.com", "Google Tag Manager", "Analytics"),
    ("doubleclick.net", "Google Ads", "Advertising"), ("googlesyndication.com", "Google Ads", "Advertising"),
    ("connect.facebook.net", "Meta Pixel", "Advertising"), ("facebook.com", "Meta", "Advertising"),
    ("hotjar.com", "Hotjar", "Analytics"), ("segment.io", "Segment", "Analytics"), ("segment.com", "Segment", "Analytics"),
    ("mixpanel.com", "Mixpanel", "Analytics"), ("amplitude.com", "Amplitude", "Analytics"), ("fullstory.com", "FullStory", "Analytics"),
    ("clarity.ms", "Microsoft Clarity", "Analytics"), ("heap.io", "Heap", "Analytics"), ("plausible.io", "Plausible", "Analytics"),
    ("stripe.com", "Stripe", "Payments"), ("stripe.network", "Stripe", "Payments"), ("paypal.com", "PayPal", "Payments"),
    ("paypalobjects.com", "PayPal", "Payments"), ("braintreegateway.com", "Braintree", "Payments"), ("adyen.com", "Adyen", "Payments"),
    ("razorpay.com", "Razorpay", "Payments"), ("checkout.com", "Checkout.com", "Payments"),
    ("intercom.io", "Intercom", "Support"), ("intercomcdn.com", "Intercom", "Support"), ("zendesk.com", "Zendesk", "Support"),
    ("zdassets.com", "Zendesk", "Support"), ("crisp.chat", "Crisp", "Support"), ("drift.com", "Drift", "Support"),
    ("tawk.to", "Tawk.to", "Support"), ("hubspot.com", "HubSpot", "Marketing"), ("hs-scripts.com", "HubSpot", "Marketing"),
    ("sentry.io", "Sentry", "Monitoring"), ("sentry-cdn.com", "Sentry", "Monitoring"), ("datadoghq.com", "Datadog", "Monitoring"),
    ("newrelic.com", "New Relic", "Monitoring"), ("nr-data.net", "New Relic", "Monitoring"), ("bugsnag.com", "Bugsnag", "Monitoring"),
    ("rollbar.com", "Rollbar", "Monitoring"), ("logrocket.com", "LogRocket", "Monitoring"),
    ("auth0.com", "Auth0", "Identity"), ("okta.com", "Okta", "Identity"), ("amazoncognito.com", "AWS Cognito", "Identity"),
    ("firebaseapp.com", "Firebase", "Identity"), ("firebaseio.com", "Firebase", "Identity"), ("clerk.com", "Clerk", "Identity"),
    ("hcaptcha.com", "hCaptcha", "Bot protection"), ("challenges.cloudflare.com", "Cloudflare Turnstile", "Bot protection"),
    ("fonts.googleapis.com", "Google Fonts", "Assets"), ("fonts.gstatic.com", "Google Fonts", "Assets"),
    ("use.fontawesome.com", "Font Awesome", "Assets"), ("kit.fontawesome.com", "Font Awesome", "Assets"),
    ("cdnjs.cloudflare.com", "cdnjs", "Assets"), ("cdn.jsdelivr.net", "jsDelivr", "Assets"), ("unpkg.com", "unpkg", "Assets"),
    ("ajax.googleapis.com", "Google Hosted Libraries", "Assets"), ("cloudinary.com", "Cloudinary", "Assets"), ("imgix.net", "imgix", "Assets"),
    ("youtube.com", "YouTube", "Media"), ("ytimg.com", "YouTube", "Media"), ("vimeo.com", "Vimeo", "Media"),
    ("maps.googleapis.com", "Google Maps", "Maps"), ("mapbox.com", "Mapbox", "Maps"),
    ("algolia.net", "Algolia", "Search"), ("algolianet.com", "Algolia", "Search"),
    ("cookiebot.com", "Cookiebot", "Consent"), ("onetrust.com", "OneTrust", "Consent"), ("cookielaw.org", "OneTrust", "Consent"),
    ("optimizely.com", "Optimizely", "Experiments"), ("launchdarkly.com", "LaunchDarkly", "Experiments"),
    ("azureedge.net", "Azure CDN", "Edge & CDN"), ("akamaihd.net", "Akamai", "Edge & CDN"), ("fastly.net", "Fastly", "Edge & CDN"),
    ("b-cdn.net", "Bunny CDN", "Edge & CDN"), ("cloudfront.net", "Amazon CloudFront", "Edge & CDN"),
]
SERVICE_KIND = {"reCAPTCHA": "Bot protection"}
_RECAPTCHA = re.compile(r"google\.com/recaptcha|gstatic\.com/recaptcha|grecaptcha", re.I)

_HEAD = [(h, re.compile(rx, re.I), n, c) for h, rx, n, c in _HEADER_SIGNS]
_COOK = [(re.compile(rx, re.I), n, c) for rx, n, c in _COOKIE_SIGNS]
_BODY = [(re.compile(rx, re.I), n, c) for rx, n, c in _BODY_SIGNS]
_PATH = [(re.compile(rx, re.I), n, c) for rx, n, c in _PATH_SIGNS]
_SCAN_CAP = 400_000


def detect(headers: dict[str, str], cookie_names: list[str], body: str, path: str,
           is_markup: bool) -> list[tuple[str, str, str, str]]:
    """Technologies one response shows: (name, category, how, version). Deterministic, deduplicated."""
    found: dict[tuple[str, str], tuple[str, str]] = {}

    def add(name, cat, how, ver=""):
        k = (name, cat)
        if k not in found or (ver and not found[k][1]):
            found[k] = (how, ver or (found[k][1] if k in found else ""))

    for h, rx, name, cat in _HEAD:
        v = headers.get(h)
        if v:
            m = rx.search(v)
            if m:
                add(name, cat, "header:" + h, (m.group(1) if m.groups() and m.group(1) else "")[:20])
    for ck in cookie_names or []:
        for rx, name, cat in _COOK:
            if rx.search(ck):
                add(name, cat, "cookie")
    for rx, name, cat in _PATH:
        if rx.search(path or ""):
            add(name, cat, "path")
    if is_markup and body:
        text = body[:_SCAN_CAP]
        for rx, name, cat in _BODY:
            m = rx.search(text)
            if m:
                add(name, cat, "page", (m.group(1) if m.groups() and m.group(1) else "")[:20])
        g = _GENERATOR.search(text)
        if g:
            gen = g.group(1).strip()[:60]
            nm = re.match(r"([A-Za-z][\w .+-]*?)(?:\s+([\d][\w.]*))?$", gen)
            name, ver = (nm.group(1).strip(), nm.group(2) or "") if nm else (gen, "")
            low = name.lower()
            if low.startswith("wordpress"):
                name = "WordPress"
            add(name, "CMS & platform", "meta generator", ver)
        if _RECAPTCHA.search(text):
            add("reCAPTCHA", "Services", "page")
    return sorted((n, c, h, v) for (n, c), (h, v) in found.items())


def vendors_for(hosts: list[str]) -> list[tuple[str, str, str]]:
    """(vendor, kind, host) for hosts that belong to a known third-party service."""
    out, seen = [], set()
    for host in hosts:
        h = (host or "").lower()
        for suffix, vendor, kind in _VENDORS:
            if h == suffix or h.endswith("." + suffix):
                if (vendor, h) not in seen:
                    seen.add((vendor, h))
                    out.append((vendor, kind, h))
                break
    return out
