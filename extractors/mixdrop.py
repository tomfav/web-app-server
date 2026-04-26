import logging
import random
import re
import base64
import asyncio
import os
from urllib.parse import urlparse, urljoin, urlencode

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector, ProxyError as AioProxyError
from python_socks import ProxyError as PyProxyError

from config import (
    FLARESOLVERR_URL, 
    FLARESOLVERR_TIMEOUT, 
    get_proxy_for_url, 
    TRANSPORT_ROUTES, 
    GLOBAL_PROXIES, 
    get_connector_for_proxy, 
    get_solver_proxy_url,
    SELECTED_PROXY_CONTEXT
)
from utils.packed import eval_solver, UnpackingError
from utils.proxy_manager import FreeProxyManager
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

from extractors.base import BaseExtractor, ExtractorError

class MixdropExtractor(BaseExtractor):
    """Mixdrop URL extractor optimized with FlareSolverr sessions."""

    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies, extractor_name="mixdrop")
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.last_used_proxy = None

    def _build_session_for_proxy(self, proxy: str | None) -> ClientSession:
        timeout = ClientTimeout(total=60, connect=30, sock_read=30)
        if proxy:
            connector = get_connector_for_proxy(proxy)
        else:
            connector = TCPConnector(limit=0, use_dns_cache=True)
        return ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)

    async def _get_auto_proxy_pool(self, url: str, headers: dict) -> list[str]:
        if os.environ.get("MIXDROP_ENABLE_FREE_PROXY_POOL", "true").lower() != "true":
            return []

        def probe_sync(proxy_url: str) -> bool:
            try:
                import cloudscraper
                scraper = cloudscraper.create_scraper(delay=2)
                resp = scraper.get(
                    url,
                    headers=headers,
                    timeout=6,
                    proxies={"http": proxy_url, "https": proxy_url},
                )
                return resp.status_code == 200 and len(resp.text) > 100
            except Exception:
                return False

        return await self.proxy_manager.get_next_sequence(probe_sync)

    async def _try_free_proxy_fallback(self, url: str, headers: dict):
        """Tries to fetch the URL using the free proxy pool."""
        for proxy_url in await self._get_auto_proxy_pool(url, headers):
            logger.info("Mixdrop: retrying with auto proxy %s", proxy_url)
            temp_session = None
            try:
                temp_session = self._build_session_for_proxy(proxy_url)
                # For Mixdrop, we call eval_solver which handles the request
                patterns = [
                    r'MDCore.wurl ?= ?\"(.*?)\"',
                    r'wurl ?= ?\"(.*?)\"',
                    r'src: ?\"(.*?)\"',
                    r'file: ?\"(.*?)\"',
                    r'https?://[^\"\']+\.mp4[^\"\']*'
                ]
                final_url = await eval_solver(temp_session, url, headers, patterns)
                if final_url:
                    self.session = temp_session
                    self.last_used_proxy = proxy_url
                    logger.info("Mixdrop: free proxy fallback succeeded with %s", proxy_url)
                    return final_url
            except Exception as proxy_exc:
                logger.warning("Mixdrop: auto proxy %s failed: %s", proxy_url, proxy_exc)
                self.proxy_manager.report_failure(proxy_url)
            finally:
                if temp_session and temp_session is not self.session and not temp_session.closed:
                    await temp_session.close()
        return None

    async def _request_flaresolverr(self, cmd: str, url: str = None, post_data: str = None, session_id: str = None) -> dict:
        """Performs a request via FlareSolverr."""
        if not FLARESOLVERR_URL:
             return None

        endpoint = f"{FLARESOLVERR_URL.rstrip('/')}/v1"
        payload = {
            "cmd": cmd,
            "maxTimeout": (FLARESOLVERR_TIMEOUT + 60) * 1000,
        }
        fs_headers = {}
        if url: 
            payload["url"] = url
            # Determina dinamicamente il proxy per questo specifico URL
            proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies)
            if proxy:
                payload["proxy"] = {"url": proxy}
                solver_proxy = get_solver_proxy_url(proxy)
                fs_headers["X-Proxy-Server"] = solver_proxy
                logger.debug(f"Mixdrop: Passing explicit proxy to solver: {solver_proxy}")

        if post_data: payload["postData"] = post_data
        if session_id: payload["session"] = session_id

        async with aiohttp.ClientSession() as fs_session:
            try:
                async with fs_session.post(
                    endpoint,
                    json=payload,
                    headers=fs_headers,
                    timeout=aiohttp.ClientTimeout(total=FLARESOLVERR_TIMEOUT + 95),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
            except Exception:
                return None

        if data.get("status") != "ok":
            return None
        
        return data

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Mixdrop URL."""
        # 1. Handle redirectors (safego.cc, clicka.cc, etc.)
        max_redirects = 5
        redirect_count = 0
        while any(domain in url.lower() for domain in ["safego.cc", "clicka.cc", "clicka", "safelink"]) and redirect_count < max_redirects:
            logger.info("Mixdrop: solving redirector %s (attempt %s)", url, redirect_count + 1)
            new_url = await self._solve_redirector(url)
            if new_url == url:
                break
            url = new_url
            redirect_count += 1

        # 2. Normalize
        if "/f/" in url: url = url.replace("/f/", "/e/")
        if "/emb/" in url: url = url.replace("/emb/", "/e/")
        
        known_mirrors = ["mixdrop.to", "m1xdrop.net", "mixdrop.bz", "mixdrop.si", 
                         "mixdrop.ag", "mixdrop.top", "mixdrop.sx", "mdy48tn97.com"]
        
        mirror_found = False
        for mirror in known_mirrors:
            if mirror in url:
                mirror_found = True
                break
        
        if not mirror_found and "mixdrop" in url:
            parts = url.split("/")
            if len(parts) > 2:
                parts[2] = "mixdrop.to"
                url = "/".join(parts)

        # Mixdrop extraction usually doesn't need FlareSolverr sessions for eval_solver
        # but we use standard aiohttp for the final packed JS extraction.
        headers = {"accept-language": "en-US,en;q=0.5", "referer": url}
        
        patterns = [
            r'MDCore.wurl ?= ?\"(.*?)\"',  # Primary pattern
            r'wurl ?= ?\"(.*?)\"',          # Simplified pattern
            r'src: ?\"(.*?)\"',             # Alternative pattern
            r'file: ?\"(.*?)\"',            # Another alternative
            r'https?://[^\"\']+\.mp4[^\"\']*'  # Direct MP4 URL pattern
        ]

        retries = 3
        initial_delay = 2
        
        for attempt in range(retries):
            try:
                session = await self._get_session(url)
                logger.info("Mixdrop: Attempt %s/%s for URL: %s", attempt + 1, retries, url)
                
                final_url = await eval_solver(session, url, headers, patterns)
                
                if not final_url or len(final_url) < 10:
                    raise ExtractorError(f"Extracted URL appears invalid: {final_url}")
                
                logger.info(f"Successfully extracted Mixdrop URL: {final_url[:50]}...")
                
                res_headers = self.base_headers.copy()
                res_headers["Referer"] = url
                return {
                    "destination_url": final_url,
                    "request_headers": res_headers,
                    "mediaflow_endpoint": self.mediaflow_endpoint,
                    "selected_proxy": self.last_used_proxy
                }

            except (
                aiohttp.ClientConnectionError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientPayloadError,
                asyncio.TimeoutError,
                OSError,
                ConnectionResetError,
                AioProxyError,
                PyProxyError,
                UnpackingError
            ) as e:
                # Se è un errore di video non trovato (UnpackingError specifico), non riprovare
                if isinstance(e, UnpackingError) and "not found" in str(e).lower():
                    raise ExtractorError(f"Mixdrop content not found: {str(e)}")

                is_proxy_err = isinstance(e, (AioProxyError, PyProxyError)) or (
                    isinstance(e, UnpackingError) and isinstance(getattr(e, "__cause__", None), (AioProxyError, PyProxyError))
                )
                is_timeout = isinstance(e, asyncio.TimeoutError) or (
                    isinstance(e, UnpackingError) and isinstance(getattr(e, "__cause__", None), asyncio.TimeoutError)
                )
                err_type = "Proxy" if is_proxy_err else ("Timeout" if is_timeout else "Connection")
                
                logger.warning(
                    "Mixdrop: %s error attempt %s for %s: %s", err_type, attempt + 1, url, str(e)
                )

                # Reset session
                if self.session and not self.session.closed:
                    try:
                        await self.session.close()
                    except Exception:
                        pass
                self.session = None
                
                if is_proxy_err and SELECTED_PROXY_CONTEXT.get():
                    logger.info("Mixdrop: Clearing sticky proxy context due to ProxyError")
                    SELECTED_PROXY_CONTEXT.set(None)

                # Try free proxy fallback if primary fails with proxy/timeout error on first attempt
                if (is_proxy_err or is_timeout) and attempt == 0:
                    logger.info("Mixdrop: primary connection failed with %s, trying free proxy fallback", err_type)
                    fallback_url = await self._try_free_proxy_fallback(url, headers)
                    if fallback_url:
                        res_headers = self.base_headers.copy()
                        res_headers["Referer"] = url
                        return {
                            "destination_url": fallback_url,
                            "request_headers": res_headers,
                            "mediaflow_endpoint": self.mediaflow_endpoint,
                            "selected_proxy": self.last_used_proxy
                        }

                if attempt < retries - 1:
                    delay = initial_delay * (2**attempt)
                    logger.info("Mixdrop: Waiting %s seconds before next attempt...", delay)
                    await asyncio.sleep(delay)
                else:
                    raise ExtractorError(f"Mixdrop: All {retries} attempts failed for {url}: {str(e)}")

            except Exception as e:
                logger.error("Mixdrop: Unexpected error attempt %s: %s", attempt + 1, str(e))
                if attempt == retries - 1:
                    raise ExtractorError(f"Mixdrop: Final error for {url}: {str(e)}")
                await asyncio.sleep(initial_delay)

    async def _solve_redirector(self, url: str) -> str:
        """Solves safego.cc or clicka.cc redirectors using FS sessions."""
        session_id = None
        current_url = url
        try:
            import ddddocr
        except ImportError:
            ddddocr = None

        try:
            res_s = await self._request_flaresolverr("sessions.create")
            if not res_s: return url
            session_id = res_s.get("session")

            res = await self._request_flaresolverr("request.get", url, session_id=session_id)
            if not res: return url
            solution = res.get("solution", {})
            text = solution.get("response", "")
            current_url = solution.get("url", url)

            soup = BeautifulSoup(text, "lxml")
            
            img_tag = soup.find("img", src=re.compile(r'data:image/png;base64,'))
            if img_tag and ddddocr:
                img_data = base64.b64decode(img_tag["src"].split(",")[1])
                ocr = ddddocr.DdddOcr(show_ad=False)
                captcha = ocr.classification(img_data)
                # Normalize common OCR errors
                captcha = captcha.replace('o', '0').replace('O', '0').replace('l', '1').replace('I', '1')
                captcha = re.sub(r'[^0-9]', '', captcha)
                logger.info("Mixdrop: Decoded captcha (normalized): %s", captcha)
                
                # Dynamic form fields extraction
                form = soup.find("form")
                post_fields = {}
                if form:
                    for inp in form.find_all("input"):
                        name = inp.get("name")
                        val = inp.get("value", "")
                        if name:
                            post_fields[name] = val
                
                # Override or add captcha code
                # On safego.cc, the field name is 'code' but the id is 'captch5'
                if "code" in post_fields or soup.find("input", {"name": "code"}):
                    post_fields["code"] = captcha
                elif "captch5" in post_fields or soup.find("input", {"name": "captch5"}):
                    post_fields["captch5"] = captcha
                else:
                    post_fields["code"] = captcha # Fallback
                
                if "submit" not in post_fields:
                    post_fields["submit"] = "Continue"
                
                post_data = urlencode(post_fields)
                logger.debug("Mixdrop: Posting captcha with data: %s", post_data)
                
                pres = await self._request_flaresolverr("request.post", current_url, post_data, session_id=session_id)
                if pres:
                    text = pres.get("solution", {}).get("response", "")
                    current_url = pres.get("solution", {}).get("url", current_url)
                    soup = BeautifulSoup(text, "lxml")

            for attempt in range(4):
                proceed_link = None
                # Check for links or buttons with specific text
                for a_tag in soup.find_all(["a", "button"], href=True) or soup.find_all(["a", "button"]):
                    txt = a_tag.get_text().lower()
                    if any(x in txt for x in ["proceed", "continue", "prosegui", "avanti", "click here", "clicca qui", "vai al video"]):
                        if a_tag.name == "a" and a_tag.get("href"):
                            proceed_link = a_tag
                        elif a_tag.name == "button" and a_tag.parent.name == "a":
                            proceed_link = a_tag.parent
                        break
                
                if not proceed_link:
                    # Look for links containing keywords
                    proceed_link = soup.find("a", href=re.compile(r'deltabit|mixdrop|clicka|safego|safelink', re.I))
                
                if proceed_link:
                    resolved_url = urljoin(current_url, proceed_link["href"])
                    if resolved_url != current_url:
                        return resolved_url
                
                # Check for meta refresh
                meta = soup.find("meta", attrs={"http-equiv": re.compile(r'refresh', re.I)})
                if meta and "url=" in meta.get("content", "").lower():
                    r_url = re.search(r'url=(.*)', meta["content"], re.I).group(1).strip()
                    if r_url: 
                        resolved_url = urljoin(current_url, r_url)
                        if resolved_url != current_url:
                            return resolved_url

                if attempt < 3:
                    await asyncio.sleep(4)
                    res = await self._request_flaresolverr("request.get", current_url, session_id=session_id)
                    if res:
                        text = res.get("solution", {}).get("response", "")
                        soup = BeautifulSoup(text, "lxml")
            
            return current_url

        finally:
            if session_id:
                try:
                    await self._request_flaresolverr("sessions.destroy", session_id=session_id)
                except Exception:
                    pass

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
