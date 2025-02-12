# reconpro/core/scraper.py
import asyncio
import aiohttp
import logging
from bs4 import BeautifulSoup

async def fetch_page(session, url):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        logging.error("Error fetching %s: %s", url, e)
        return ""

async def scrape_urls(urls, depth=1):
    discovered = set()
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_page(session, url) for url in urls]
        pages = await asyncio.gather(*tasks)
        for content in pages:
            if content:
                discovered.update(extract_links(content))
        # Optionally, recursively scrape newly discovered links.
        if depth > 0 and discovered:
            discovered_recursive = await scrape_urls(list(discovered), depth-1)
            discovered.update(discovered_recursive)
    logging.info("Discovered %d additional URLs via scraping", len(discovered))
    return discovered

def extract_links(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        links.add(tag["href"])
    return links
