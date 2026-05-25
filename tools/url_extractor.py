import re
from typing import List

_URL_PATTERN = re.compile(
    r"https?://[^\s\"\'>)\]]+|"
    r"www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\"\'>)\]]*",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    urls = _URL_PATTERN.findall(text)
    seen = set()
    unique = []
    for url in urls:
        url = url.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique
