import re
import logging
from urllib.parse import urlparse, urljoin, parse_qs
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from backend.config import Config

logger = logging.getLogger(__name__)

class PlaywrightCrawler:
    def __init__(self, target_url: str, depth: str = "quick"):
        self.target_url = target_url
        self.depth = depth.lower() if depth.lower() in Config.DEPTH_LIMITS else "quick"
        self.max_pages = Config.DEPTH_LIMITS.get(self.depth, 5)
        self.target_domain = urlparse(target_url).netloc
        self.visited = set()
        self.forms = []
        self.query_params = []
        self.title = ""
        self.final_url = target_url
        self.logs = []

    def _log(self, message: str, level: str = "INFO"):
        log_entry = f"[{level}] {message}"
        self.logs.append(log_entry)
        logger.info(log_entry)

    def _is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.target_domain or not parsed.netloc

    def _extract_query_params(self, url: str):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for key, values in qs.items():
            param_obj = {"url": url, "param": key, "sample_val": values[0] if values else ""}
            if param_obj not in self.query_params:
                self.query_params.append(param_obj)

    def crawl(self) -> dict:
        self._log(f"Starting web crawler for {self.target_url} (Depth: {self.depth}, Max Pages: {self.max_pages})")
        queue = [self.target_url]
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=Config.PLAYWRIGHT_HEADLESS)
                context = browser.new_context(
                    user_agent="WebsiteVulnerabilityScanner/1.0",
                    ignore_https_errors=True
                )
                page = context.new_page()
                page.set_default_timeout(Config.CRAWL_TIMEOUT_MS)

                while queue and len(self.visited) < self.max_pages:
                    current_url = queue.pop(0)
                    if current_url in self.visited:
                        continue

                    self.visited.add(current_url)
                    self._extract_query_params(current_url)
                    self._log(f"Crawling page ({len(self.visited)}/{self.max_pages}): {current_url}")

                    try:
                        response = page.goto(current_url, wait_until="domcontentloaded")
                        if len(self.visited) == 1:
                            self.final_url = page.url
                            self.title = page.title() or "Untitled Page"
                            self._log(f"Target page loaded. Title: '{self.title}'")

                        # Extract forms
                        form_elements = page.query_selector_all("form")
                        for form in form_elements:
                            action = form.get_attribute("action") or current_url
                            method = (form.get_attribute("method") or "GET").upper()
                            full_action = urljoin(current_url, action)

                            inputs = []
                            for inp in form.query_selector_all("input, select, textarea"):
                                inp_name = inp.get_attribute("name")
                                if inp_name:
                                    inputs.append({
                                        "name": inp_name,
                                        "type": inp.get_attribute("type") or "text",
                                        "value": inp.get_attribute("value") or ""
                                    })

                            form_data = {
                                "page_url": current_url,
                                "action": full_action,
                                "method": method,
                                "inputs": inputs
                            }
                            if form_data not in self.forms:
                                self.forms.append(form_data)

                        # Extract internal links
                        anchors = page.query_selector_all("a[href]")
                        for anchor in anchors:
                            href = anchor.get_attribute("href")
                            if href and not href.startswith("#") and not href.startswith("javascript:"):
                                abs_url = urljoin(current_url, href)
                                clean_url = abs_url.split("#")[0]
                                if self._is_same_domain(clean_url) and clean_url not in self.visited and clean_url not in queue:
                                    queue.append(clean_url)

                    except PlaywrightTimeoutError:
                        self._log(f"Timeout crawling page: {current_url}", "WARN")
                    except Exception as e:
                        self._log(f"Error crawling {current_url}: {str(e)}", "WARN")

                context.close()
                browser.close()
                self._log(f"Crawling completed. {len(self.visited)} pages crawled, {len(self.forms)} forms discovered.")

        except Exception as e:
            self._log(f"Crawler failure: {str(e)}", "ERROR")

        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "title": self.title,
            "pages_crawled": len(self.visited),
            "discovered_links": list(self.visited),
            "forms": self.forms,
            "query_params": self.query_params,
            "logs": self.logs
        }
