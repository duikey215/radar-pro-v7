from fastapi import FastAPI, Query
import httpx
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
import random
from datetime import datetime

app = FastAPI()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9'
}

async def fetch_page(client, url):
    try:
        # Stealth Jitter
        await asyncio.sleep(random.uniform(0.1, 0.4))
        resp = await client.get(url, timeout=8.0, follow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')
        text = soup.get_text().lower()
        return {
            "status": resp.status_code,
            "words": len(text.split()),
            "text": text,
            "loop": len(resp.history) >= 3,
            "h1s": len(soup.find_all('h1'))
        }
    except:
        return {"status": 0, "words": 0, "text": "", "loop": False, "h1s": 0}

@app.get("/api/audit")
async def audit(url: str = Query(...)):
    start_time = time.time()
    if not url.startswith("http"):
        return {"error": "Invalid URL"}

    async with httpx.AsyncClient(headers=HEADERS, verify=False) as client:
        # Step 1: Homepage & Links
        try:
            home_res = await client.get(url, timeout=10.0, follow_redirects=True)
            home_soup = BeautifulSoup(home_res.text, 'html.parser')
            home_text = home_soup.get_text().lower()
        except:
            return {"error": "Could not connect to website"}

        links = home_soup.find_all('a', href=True)
        internal_urls = list(set([urljoin(url, a['href']).split('#')[0] for a in links 
                                 if urlparse(urljoin(url, a['href'])).netloc == urlparse(url).netloc]))
        
        scan_list = internal_urls[:50]
        if url not in scan_list: scan_list.insert(0, url)

        # Step 2: Parallel Deep Scan (Ultra Fast)
        tasks = [fetch_page(client, u) for u in scan_list]
        pages_results = await asyncio.gather(*tasks)

        # Step 3: Analysis Logic (NO TRIMMING)
        total_words = sum(p['words'] for p in pages_results)
        valid_pages = [p for p in pages_results if p['words'] > 0]
        avg_words = total_words // len(valid_pages) if valid_pages else 0
        s_404 = sum(1 for p in pages_results if p['status'] >= 400)
        redirect_loops = sum(1 for p in pages_results if p['loop'])
        combined_text = " ".join([p['text'] for p in pages_results])
        
        # Policy & SEO Checks
        has_ssl = url.startswith("https")
        essentials = [ep for ep in ["privacy", "contact", "about", "disclaimer", "terms"] if any(ep in u.lower() for u in internal_urls)]
        banned = [w for w in ["hack", "cracked", "mod apk", "adult", "casino", "porn", "violence"] if w in combined_text]
        
        h1_count = len(home_soup.find_all('h1'))
        has_robots = True # Simplified for speed
        has_sitemap = True 

        # Final Scoring
        score = 100
        advice = []
        if not has_ssl: score -= 15; advice.append("Install SSL (HTTPS).")
        if s_404 > 0: score -= 15; advice.append(f"Fix {s_404} broken links.")
        if len(essentials) < 4: score -= 20; advice.append("Add missing Policy pages.")
        if banned: score -= 30; advice.append(f"Remove prohibited content: {', '.join(set(banned))}")
        if avg_words < 600: score -= 15; advice.append(f"Thin content (Avg {avg_words} words). Aim for 600+.")
        
        return {
            "score": max(0, score),
            "load_time": round(time.time() - start_time, 2),
            "pages_scanned": len(pages_results),
            "avg_words": avg_words,
            "s_404": s_404,
            "redirect_loops": redirect_loops,
            "essentials_found": len(essentials),
            "banned_found": list(set(banned)),
            "h1_count": h1_count,
            "has_ssl": has_ssl,
            "advice": advice
        }  
