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

    def _extract_inputs_from_form_element(self, form_element, current_url):
        """Extract all testable input fields from a Playwright form element."""
        inputs = []
        # Include all input types relevant to security testing
        SKIP_TYPES = {"submit", "button", "image", "reset", "file"}
        for inp in form_element.query_selector_all("input, select, textarea"):
            inp_name = inp.get_attribute("name")
            inp_type = (inp.get_attribute("type") or "text").lower()
            if inp_name and inp_type not in SKIP_TYPES:
                inputs.append({
                    "name": inp_name,
                    "type": inp_type,
                    "value": inp.get_attribute("value") or ""
                })
        return inputs

    def crawl(self) -> dict:
        self._log(f"Starting web crawler for {self.target_url} (Depth: {self.depth}, Max Pages: {self.max_pages})")
        queue = [self.target_url]

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=Config.PLAYWRIGHT_HEADLESS)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (compatible; WebsiteVulnerabilityScanner/2.0)",
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
                        page.goto(current_url, wait_until="domcontentloaded")
                        if len(self.visited) == 1:
                            self.final_url = page.url
                            self.title = page.title() or "Untitled Page"
                            self._log(f"Target page loaded. Title: '{self.title}'")

                        # Extract forms with all input types
                        form_elements = page.query_selector_all("form")
                        for form in form_elements:
                            action = form.get_attribute("action") or current_url
                            method = (form.get_attribute("method") or "GET").upper()
                            full_action = urljoin(current_url, action)
                            inputs = self._extract_inputs_from_form_element(form, current_url)
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
            self._log(f"Playwright browser engine encountered an issue: {str(e)}. Activating HTTP crawler fallback...", "WARN")
            self._fallback_crawl(queue if queue else [self.target_url])

        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "title": self.title or "Web Application",
            "pages_crawled": len(self.visited),
            "discovered_links": list(self.visited),
            "forms": self.forms,
            "query_params": self.query_params,
            "logs": self.logs
        }

    def _fallback_crawl(self, queue: list):
        """
        Robust HTTP-based fallback crawler using BeautifulSoup for proper HTML parsing.
        Replaces the fragile regex-based approach.
        """
        import requests
        try:
            from bs4 import BeautifulSoup
            use_bs4 = True
        except ImportError:
            use_bs4 = False
            self._log("BeautifulSoup not available, using basic regex fallback.", "WARN")

        # Reset visited to avoid double-counting from partial Playwright run
        if not self.visited:
            queue = [self.target_url]

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; WebsiteVulnerabilityScanner/2.0)"
        })

        SKIP_TYPES = {"submit", "button", "image", "reset", "file"}

        while queue and len(self.visited) < self.max_pages:
            current_url = queue.pop(0)
            if current_url in self.visited:
                continue

            self.visited.add(current_url)
            self._extract_query_params(current_url)
            self._log(f"[Fallback] Crawling page ({len(self.visited)}/{self.max_pages}): {current_url}")

            try:
                res = session.get(current_url, timeout=10, verify=False)
                if len(self.visited) == 1:
                    self.final_url = res.url

                if use_bs4:
                    soup = BeautifulSoup(res.text, "html.parser")

                    # Extract page title
                    if len(self.visited) == 1:
                        title_tag = soup.find("title")
                        self.title = title_tag.get_text(strip=True) if title_tag else "Untitled"
                        self._log(f"[Fallback] Title: '{self.title}'")

                    # Extract all links
                    for tag in soup.find_all("a", href=True):
                        href = tag["href"]
                        if href and not href.startswith("#") and not href.startswith("javascript:") and not href.startswith("mailto:"):
                            abs_url = urljoin(current_url, href).split("#")[0]
                            if self._is_same_domain(abs_url) and abs_url not in self.visited and abs_url not in queue:
                                queue.append(abs_url)

                    # Extract all forms with proper input parsing
                    for form_tag in soup.find_all("form"):
                        action_raw = form_tag.get("action", "") or current_url
                        method = (form_tag.get("method", "GET") or "GET").upper()
                        full_action = urljoin(current_url, action_raw)

                        inputs = []
                        # Parse all input types
                        for inp in form_tag.find_all("input"):
                            name = inp.get("name", "")
                            inp_type = (inp.get("type", "text") or "text").lower()
                            if name and inp_type not in SKIP_TYPES:
                                inputs.append({
                                    "name": name,
                                    "type": inp_type,
                                    "value": inp.get("value", "") or ""
                                })

                        # Parse <textarea> elements
                        for ta in form_tag.find_all("textarea"):
                            name = ta.get("name", "")
                            if name:
                                inputs.append({
                                    "name": name,
                                    "type": "textarea",
                                    "value": ta.get_text() or ""
                                })

                        # Parse <select> elements
                        for sel in form_tag.find_all("select"):
                            name = sel.get("name", "")
                            if name:
                                # Get first option value as sample
                                first_opt = sel.find("option")
                                val = first_opt.get("value", "") if first_opt else ""
                                inputs.append({
                                    "name": name,
                                    "type": "select",
                                    "value": val
                                })

                        form_data = {
                            "page_url": current_url,
                            "action": full_action,
                            "method": method,
                            "inputs": inputs
                        }
                        if form_data not in self.forms:
                            self.forms.append(form_data)

                else:
                    # Basic regex fallback when bs4 unavailable
                    if len(self.visited) == 1:
                        title_match = re.search(r"<title>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            self.title = title_match.group(1).strip()
                        self._log(f"[Fallback] Title: '{self.title}'")

                    hrefs = re.findall(r'href=[\'""]?([^\'"" >]+)', res.text, re.IGNORECASE)
                    for href in hrefs:
                        if href and not href.startswith("#") and not href.startswith("javascript:"):
                            abs_url = urljoin(current_url, href).split("#")[0]
                            if self._is_same_domain(abs_url) and abs_url not in self.visited and abs_url not in queue:
                                queue.append(abs_url)

                    forms_html = re.findall(r'<form[\s\S]*?</form>', res.text, re.IGNORECASE)
                    for f_html in forms_html:
                        action_m = re.search(r'action=[\'""]?([^\'"" >]*)', f_html, re.IGNORECASE)
                        action = action_m.group(1) if action_m else current_url
                        method_m = re.search(r'method=[\'""]?([^\'"" >]*)', f_html, re.IGNORECASE)
                        method = (method_m.group(1) if method_m else "GET").upper()
                        inputs = []
                        for inp_tag in re.findall(r'<input[\s\S]*?>', f_html, re.IGNORECASE):
                            name_m = re.search(r'name=[\'""]?([^\'"" >]*)', inp_tag, re.IGNORECASE)
                            type_m = re.search(r'type=[\'""]?([^\'"" >]*)', inp_tag, re.IGNORECASE)
                            val_m = re.search(r'value=[\'""]?([^\'"" >]*)', inp_tag, re.IGNORECASE)
                            if name_m and name_m.group(1):
                                inp_type = (type_m.group(1) if type_m else "text").lower()
                                if inp_type not in SKIP_TYPES:
                                    inputs.append({
                                        "name": name_m.group(1),
                                        "type": inp_type,
                                        "value": val_m.group(1) if val_m else ""
                                    })
                        form_data = {
                            "page_url": current_url,
                            "action": urljoin(current_url, action),
                            "method": method,
                            "inputs": inputs
                        }
                        if form_data not in self.forms:
                            self.forms.append(form_data)

            except Exception as e:
                self._log(f"[Fallback] Error crawling {current_url}: {str(e)}", "WARN")

        self._log(f"[Fallback] Crawl complete. {len(self.visited)} pages, {len(self.forms)} forms found.")
