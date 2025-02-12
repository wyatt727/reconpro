# reconpro/core/fuzz.py
import asyncio
import aiohttp
import logging
import difflib
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import TIMEOUT, SIMILARITY_THRESHOLD, DATA_DIR
from core.external import run_nuclei_scan, run_gf_scan

def load_payloads():
    payloads_dir = os.path.join(DATA_DIR, "payloads")
    payloads = []
    if os.path.exists(payloads_dir):
        for filename in os.listdir(payloads_dir):
            if filename.endswith(".txt"):
                with open(os.path.join(payloads_dir, filename), "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        payloads.append(content)
    return payloads

async def fuzz_get_param(session, url, param, payload):
    """
    Fuzz a URL parameter via a GET request using a shared aiohttp session.
    Offloads blocking external tool calls using asyncio.to_thread.
    """
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original = query.get(param, [""])[0]
        baseline_query = query.copy()
        baseline_query[param] = original
        baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_query, doseq=True)))
        
        async with session.get(baseline_url) as response:
            baseline_text = await response.text()
            
        fuzzed_query = query.copy()
        fuzzed_query[param] = payload
        fuzzed_url = urlunparse(parsed._replace(query=urlencode(fuzzed_query, doseq=True)))
        
        async with session.get(fuzzed_url) as response:
            fuzzed_text = await response.text()
            
        similarity = difflib.SequenceMatcher(None, baseline_text, fuzzed_text).ratio()
        if similarity < SIMILARITY_THRESHOLD:
            gf_matches = await asyncio.to_thread(run_gf_scan, fuzzed_url)
            nuclei_output = await asyncio.to_thread(run_nuclei_scan, fuzzed_url)
            record = {
                "url": fuzzed_url,
                "parameter": param,
                "payload": payload,
                "method": "GET",
                "similarity": similarity,
                "gf_matches": gf_matches,
                "nuclei_output": nuclei_output
            }
            logging.info("Vulnerability detected (GET) on %s, similarity: %.2f", fuzzed_url, similarity)
            return record
    except Exception as e:
        logging.error("Error fuzzing GET for %s [param: %s, payload: %s]: %s", url, param, payload, e)
    return None

async def fuzz_post_param(session, url, param, payload):
    """
    Fuzz a URL parameter via a POST request using a shared aiohttp session.
    Offloads blocking external tool calls using asyncio.to_thread.
    """
    try:
        baseline_data = {param: ""}
        async with session.post(url, json=baseline_data) as response:
            baseline_text = await response.text()
            
        fuzzed_data = {param: payload}
        async with session.post(url, json=fuzzed_data) as response:
            fuzzed_text = await response.text()
            
        similarity = difflib.SequenceMatcher(None, baseline_text, fuzzed_text).ratio()
        if similarity < SIMILARITY_THRESHOLD:
            gf_matches = await asyncio.to_thread(run_gf_scan, url)
            nuclei_output = await asyncio.to_thread(run_nuclei_scan, url)
            record = {
                "url": url,
                "parameter": param,
                "payload": payload,
                "method": "POST",
                "similarity": similarity,
                "gf_matches": gf_matches,
                "nuclei_output": nuclei_output
            }
            logging.info("Vulnerability detected (POST) on %s, similarity: %.2f", url, similarity)
            return record
    except Exception as e:
        logging.error("Error fuzzing POST for %s [param: %s, payload: %s]: %s", url, param, payload, e)
    return None
