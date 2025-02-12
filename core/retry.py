import asyncio
import aiohttp
import logging

async def fetch_with_retry(session, method, url, *, json_payload=None, retries=3, delay=2):
    for attempt in range(1, retries + 1):
        try:
            if method.upper() == "GET":
                async with session.get(url) as response:
                    return await response.text()
            elif method.upper() == "POST":
                async with session.post(url, json=json_payload) as response:
                    return await response.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning("Attempt %d: Error fetching %s via %s: %s", attempt, url, method, e)
            if attempt < retries:
                await asyncio.sleep(delay)
    logging.error("Failed to fetch %s via %s after %d attempts", url, method, retries)
    return ""