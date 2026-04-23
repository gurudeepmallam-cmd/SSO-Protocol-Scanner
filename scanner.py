import argparse
import asyncio
import csv
import re
import os
from urllib.parse import urlparse, parse_qs

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

AUTHORIZE_HOST_HINTS = (
    "login.microsoftonline.com",
    "login.windows.net",
    "login.microsoft.com",
    "login.live.com",
    "microsoftonline.com",
    "b2clogin.com",
)

LOGIN_TEXT_HINTS = (
    "sign in",
    "signin",
    "log in",
    "login",
    "continue",
    "sso",
    "single sign-on",
    "microsoft",
    "azure",
    "entra",
    "employee",
)


def normalize_target(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if not re.match(r"^https?://", s, re.I):
        s = "https://" + s
    return s


def looks_like_authorize(url: str) -> bool:
    try:
        u = urlparse(url)
    except Exception:
        return False

    host = (u.hostname or "").lower()
    path = (u.path or "").lower()
    ql = (u.query or "").lower()

    if any(h in host for h in AUTHORIZE_HOST_HINTS) and "/authorize" in path:
        return True
    if "/authorize" in path and "response_type=" in ql:
        return True
    if "/authorize" in path and ("client_id=" in ql or "redirect_uri=" in ql):
        return True
    return False


def looks_like_saml(url: str, method: str = "", post_data: str = "") -> bool:
    try:
        u = urlparse(url)
    except Exception:
        return False

    path = (u.path or "").lower()
    q = parse_qs(u.query)

    if "samlrequest" in q or "samlresponse" in q:
        return True
    if "/saml" in path or path.endswith("/saml2"):
        if method.upper() == "POST":
            return True
        if u.query:
            return True

    if method.upper() == "POST" and post_data:
        pd_l = post_data.lower()
        if "samlrequest=" in pd_l or "samlresponse=" in pd_l:
            return True

    return False


def looks_like_wsfed(url: str) -> bool:
    try:
        u = urlparse(url)
    except Exception:
        return False

    q = parse_qs(u.query)
    wa = (q.get("wa", [""])[0] or "").lower()
    if wa.startswith("wsignin"):
        return True

    path = (u.path or "").lower()
    if "wsfed" in path:
        return True

    return False


def classify_flow(response_type: str) -> str:
    rt = (response_type or "").lower().strip()
    parts = set(rt.split())
    if not rt:
        return "unknown_no_response_type"
    if "code" in parts and ("token" in parts or "id_token" in parts):
        return "hybrid_or_mixed"
    if "code" in parts:
        return "auth_code"
    if "token" in parts or "id_token" in parts:
        return "implicit"
    return "unknown_other"


def extract_authorize_params(authorize_url: str) -> dict:
    u = urlparse(authorize_url)
    q = parse_qs(u.query)

    def one(k: str) -> str:
        v = q.get(k, [""])
        return v[0] if v else ""

    scope = one("scope")
    response_type = one("response_type")

    is_oidc = "openid" in set((scope or "").lower().split()) or "id_token" in set(
        (response_type or "").lower().split()
    )

    return {
        "tenant_host": (u.hostname or ""),
        "client_id": one("client_id"),
        "response_type": response_type,
        "response_mode": one("response_mode"),
        "redirect_uri": one("redirect_uri"),
        "scope": scope,
        "x_client_sku": one("x-client-SKU"),
        "x_client_ver": one("x-client-VER"),
        "code_challenge_method": one("code_challenge_method"),
        "is_oidc": "true" if is_oidc else "false",
    }


def extract_saml_params(url: str, method: str = "", post_data: str = "") -> dict:
    u = urlparse(url)
    q = parse_qs(u.query)
    method_u = (method or "").upper()

    has_req_q = "SAMLRequest" in q or "samlrequest" in q
    has_resp_q = "SAMLResponse" in q or "samlresponse" in q

    has_req_body = False
    has_resp_body = False
    if method_u == "POST" and post_data:
        pd_l = post_data.lower()
        has_req_body = "samlrequest=" in pd_l
        has_resp_body = "samlresponse=" in pd_l

    relay = ""
    if "RelayState" in q:
        relay = q.get("RelayState", [""])[0]
    elif "relaystate" in q:
        relay = q.get("relaystate", [""])[0]
    elif method_u == "POST" and post_data:
        m = re.search(r"(?:^|&)(?:RelayState|relaystate)=([^&]+)", post_data)
        if m:
            relay = m.group(1)

    binding = "unknown"
    if has_req_q or has_resp_q:
        binding = "redirect"
    if has_req_body or has_resp_body:
        binding = "post"

    flow = "saml_unknown"
    if has_req_q or has_req_body:
        flow = "saml_sp_initiated_request"
    elif has_resp_q or has_resp_body:
        flow = "saml_idp_response"

    return {
        "idp_host": (u.hostname or ""),
        "saml_binding": binding,
        "saml_flow": flow,
        "relay_state": relay,
    }


def extract_wsfed_params(url: str) -> dict:
    u = urlparse(url)
    q = parse_qs(u.query)

    def one(k: str) -> str:
        v = q.get(k, [""])
        return v[0] if v else ""

    return {
        "idp_host": (u.hostname or ""),
        "wa": one("wa"),
        "wtrealm": one("wtrealm"),
        "wreply": one("wreply"),
        "wctx": one("wctx"),
    }


async def _click_first_match(locator) -> bool:
    try:
        await locator.wait_for(state="visible", timeout=1500)
    except Exception:
        return False
    try:
        await locator.scroll_into_view_if_needed(timeout=1500)
    except Exception:
        pass

    try:
        await locator.click(timeout=2500)
        return True
    except Exception:
        try:
            await locator.click(timeout=2500, force=True)
            return True
        except Exception:
            return False


async def try_trigger_login_ui(page, timeout_ms: int) -> bool:
    candidates = [
        "role=button[name=/continue\\s+to\\s+sso/i]",
        "role=link[name=/continue\\s+to\\s+sso/i]",
        "text=/continue\\s+to\\s+sso/i",
        "button:has-text('Continue to SSO')",
        "a:has-text('Continue to SSO')",
        "text=/sign\\s*in/i",
        "text=/log\\s*in/i",
        "text=/sso/i",
        "text=/single\\s*sign\\s*-?\\s*on/i",
        "text=/continue/i",
        "role=button[name=/sign\\s*in/i]",
        "role=button[name=/log\\s*in/i]",
        "role=link[name=/sign\\s*in/i]",
        "role=link[name=/log\\s*in/i]",
        "a:has-text('Sign in')",
        "a:has-text('Login')",
        "button:has-text('Sign in')",
        "button:has-text('Login')",
    ]

    end_by = asyncio.get_event_loop().time() + (timeout_ms / 1000)

    async def try_on_frame(f) -> bool:
        for sel in candidates:
            if asyncio.get_event_loop().time() > end_by:
                return False
            try:
                loc = f.locator(sel).first
                if await loc.count() == 0:
                    continue
                if await _click_first_match(loc):
                    return True
            except Exception:
                continue
        return False

    if await try_on_frame(page):
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        return True

    for fr in page.frames:
        if fr == page.main_frame:
            continue
        if await try_on_frame(fr):
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
            return True

    return False


async def scan_one(browser, target_url: str, timeout_ms: int) -> dict:
    result = {
        "input_url": target_url,
        "status": "unknown",

        "protocol": "",
        "protocol_flow": "",

        "flow": "",
        "authorize_url": "",
        "tenant_host": "",
        "client_id": "",
        "response_type": "",
        "response_mode": "",
        "code_challenge_method": "",
        "x_client_sku": "",
        "x_client_ver": "",
        "is_oidc": "",

        "saml_binding": "",
        "relay_state": "",
        "idp_host": "",

        "wa": "",
        "wtrealm": "",
        "wreply": "",
        "wctx": "",

        "auto_click_used": "",
        "notes": "",
    }

    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    found = asyncio.Event()

    def set_found(status: str):
        result["status"] = status
        found.set()

    def on_request(req):
        if found.is_set():
            return

        u = req.url
        method = (req.method or "").upper()
        post_data = req.post_data or ""

        if looks_like_authorize(u):
            p = extract_authorize_params(u)
            result["authorize_url"] = u
            result["tenant_host"] = p["tenant_host"]
            result["client_id"] = p["client_id"]
            result["response_type"] = p["response_type"]
            result["response_mode"] = p["response_mode"]
            result["code_challenge_method"] = p["code_challenge_method"]
            result["x_client_sku"] = p["x_client_sku"]
            result["x_client_ver"] = p["x_client_ver"]
            result["is_oidc"] = p["is_oidc"]
            result["flow"] = classify_flow(p["response_type"])
            result["protocol"] = "oidc" if p["is_oidc"] == "true" else "oauth2"
            result["protocol_flow"] = result["flow"]
            set_found("authorize_seen")
            return

        if looks_like_saml(u, method=method, post_data=post_data):
            p = extract_saml_params(u, method=method, post_data=post_data)
            result["protocol"] = "saml2"
            result["protocol_flow"] = p["saml_flow"]
            result["saml_binding"] = p["saml_binding"]
            result["relay_state"] = p["relay_state"]
            result["idp_host"] = p["idp_host"]
            set_found("saml_seen")
            return

        if looks_like_wsfed(u):
            p = extract_wsfed_params(u)
            result["protocol"] = "wsfed"
            result["protocol_flow"] = "wsignin"
            result["idp_host"] = p["idp_host"]
            result["wa"] = p["wa"]
            result["wtrealm"] = p["wtrealm"]
            result["wreply"] = p["wreply"]
            result["wctx"] = p["wctx"]
            set_found("wsfed_seen")
            return

    def attach_page_listeners(p):
        try:
            p.on("request", on_request)
        except Exception:
            pass

    attach_page_listeners(page)

    def on_new_page(p):
        attach_page_listeners(p)

    context.on("page", on_new_page)

    try:
        await page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)

        try:
            await asyncio.wait_for(found.wait(), timeout=min(3.0, timeout_ms / 1000))
        except asyncio.TimeoutError:
            pass

        if not found.is_set():
            clicked = await try_trigger_login_ui(page, timeout_ms=timeout_ms)
            result["auto_click_used"] = "true" if clicked else "false"

            if clicked:
                try:
                    await asyncio.wait_for(found.wait(), timeout=min(12.0, timeout_ms / 1000))
                except asyncio.TimeoutError:
                    result["status"] = "no_auth_seen_after_click"
                    result["notes"] = "Clicked login UI but no OAuth/SAML/WS-Fed request observed (possibly blocked or nonstandard endpoint)."
            else:
                result["status"] = "no_auth_seen"
                result["notes"] = "No OAuth/SAML/WS-Fed request observed; login UI not found/clickable."

    except PlaywrightTimeoutError:
        result["status"] = "timeout_loading"
        result["notes"] = "Timed out loading page."
    except Exception as e:
        result["status"] = "error_loading"
        result["notes"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            context.off("page", on_new_page)
        except Exception:
            pass
        try:
            await context.close()
        except Exception:
            pass

    return result


def _default_noauth_path(auth_path: str) -> str:
    base, ext = os.path.splitext(auth_path)
    ext = ext if ext else ".csv"
    return f"{base}_no_auth{ext}"


async def main_async(args):
    targets = []
    with open(args.infile, "r", encoding="utf-8") as f:
        for line in f:
            t = normalize_target(line)
            if t:
                targets.append(t)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=(not args.headed))

        sem = asyncio.Semaphore(args.concurrency)

        async def worker(t):
            async with sem:
                return await scan_one(browser, t, args.timeout_ms)

        results = await asyncio.gather(*(worker(t) for t in targets), return_exceptions=False)
        await browser.close()

    fields = [
        "input_url",
        "status",
        "protocol",
        "protocol_flow",
        "flow",
        "is_oidc",
        "response_type",
        "response_mode",
        "tenant_host",
        "client_id",
        "code_challenge_method",
        "x_client_sku",
        "x_client_ver",
        "authorize_url",
        "saml_binding",
        "relay_state",
        "idp_host",
        "wa",
        "wtrealm",
        "wreply",
        "wctx",
        "auto_click_used",
        "notes",
    ]

    auth_statuses = {"authorize_seen", "saml_seen", "wsfed_seen"}

    auth_rows = [r for r in results if r.get("status") in auth_statuses]
    noauth_rows = [r for r in results if r.get("status") not in auth_statuses]

    out_auth = args.outfile
    out_noauth = args.outfile_noauth or _default_noauth_path(out_auth)

    # 1st "Excel": auth seen only
    with open(out_auth, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fields)
        w.writeheader()
        for r in auth_rows:
            w.writerow({k: r.get(k, "") for k in fields})

    # 2nd "Excel": no auth (and any other non-auth statuses)
    with open(out_noauth, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fields)
        w.writeheader()
        for r in noauth_rows:
            w.writerow({k: r.get(k, "") for k in fields})


def parse_args():
    ap = argparse.ArgumentParser(
        description="Detect OAuth/OIDC /authorize, SAML2, and WS-Fed; classify flow; output CSV."
    )
    ap.add_argument("--in", dest="infile", default="url.txt", help="Input file with one URL/domain per line.")
    ap.add_argument("--out", dest="outfile", default="output.csv", help="AUTH-SEEN output CSV (1st excel).")
    ap.add_argument("--out-noauth", dest="outfile_noauth", default="", help="NO-AUTH output CSV (2nd excel).")
    ap.add_argument("--concurrency", type=int, default=5, help="Parallel pages.")
    ap.add_argument("--timeout-ms", type=int, default=15000, help="Per-target timeout in ms.")
    ap.add_argument("--headed", action="store_true", help="Run with visible browser (debug).")
    return ap.parse_args()


if __name__ == "__main__":
    asyncio.run(main_async(parse_args()))
