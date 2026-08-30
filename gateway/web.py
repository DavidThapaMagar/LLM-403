"""
Lightweight mock "browser" for testing browser-agent attacks.

Real browsing agents fetch a live page and extract its rendered (or
raw DOM/accessibility-tree) text. This mock simulates that by mapping
a small set of "URLs" to local HTML files under web_pages/ and
returning their full raw text - INCLUDING any hidden elements (CSS
display:none, HTML comments, etc.), since that's the point of this
attack class: content a human would never see rendered can still be
picked up by an automated agent reading the underlying page content.
"""

import os

WEB_PAGES_DIR = "web_pages"

MOCK_URL_REGISTRY = {
    "https://company.example.com/blog/product-updates": "company_blog.html",
    "https://company.example.com/support/faq": "support_faq.html",
    "https://vendor.example.com/status": "vendor_status_page.html",
}


def fetch_webpage(url):
    """Returns (found: bool, content: str | None) for the given mock URL."""
    filename = MOCK_URL_REGISTRY.get(url)
    if filename is None:
        return False, None
    path = os.path.join(WEB_PAGES_DIR, filename)
    try:
        with open(path) as f:
            return True, f.read()
    except OSError:
        return False, None
