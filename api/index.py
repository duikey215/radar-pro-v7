from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import random
import concurrent.futures
import re

app = FastAPI()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9'
}

def analyze_page(url):
    try:
        # Stealth Jitter
        time.sleep(random.uniform(0.1, 0.4))
        res = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(res.text, 'html.parser')
        text = soup.get_text().lower()
        return {
            "url": url,
            "status": res.status_code,
            "words": len(text.split()),
            "h1": len(soup.find_all('h1')),
            "h2": len(soup.find_all('h2')),
            "img_alt_missing": sum(1 for img in soup.find_all('img') if not img.get('alt')),
            "text_content": text,
            "redirect_loop": len(res.history) >= 3
        }
    except:
        return None

@app.get("/api/audit")
def audit(url: str = Query(...)):
    start_time = time.time()
    
    # 🛠️ URL Auto-Correction (No more https requirement)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Step 1: Initial Crawl
        base_res = requests.get(url, headers=HEADERS, timeout=12)
        base_soup = BeautifulSoup(base_res.text, 'html.parser')
        
        # Finding all internal links
        links = base_soup.find_all('a', href=True)
        domain = urlparse(url).netloc
        all_internal = list(set([urljoin(url, a['href']).split('#')[0] for a in links 
                                if urlparse(urljoin(url, a['href'])).netloc == domain]))
        
        total_discovered = len(all_internal)
        scan_list = all_internal[:50] # Deep Scan Limit
        if url not in scan_list: scan_list.insert(0, url)

        # Step 2: Multi-threaded Deep Scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(analyze_page, scan_list))
        
        results = [r for r in results if r is not None]

        # Step 3: Master Analysis Logic (NO TRIMMING)
        total_words = sum(r['words'] for r in results)
        avg_words = total_words // len(results)
        s_404 = sum(1 for r in results if r['status'] >= 400)
        loops = sum(1 for r in results if r['redirect_loop'])
        combined_text = " ".join([r['text_content'] for r in results])
        
        # Policy Checks
        essentials = [p for p in ["privacy", "terms", "about", "contact", "disclaimer"] if any(p in u.lower() for u in all_internal)]
        banned = [w for w in ["hack", "mod apk", "adult", "casino", "porn", "cracked"] if w in combined_text]
        
        # Technical
        has_ssl = url.startswith("https")
        has_adsense = "pagead2.googlesyndication.com" in base_res.text
        has_sitemap = requests.get(urljoin(url, "/sitemap.xml"), timeout=5).status_code == 200
        has_robots = requests.get(urljoin(url, "/robots.txt"), timeout=5).status_code == 200

        # Scoring Logic
        score = 100
        advice = []
        if not has_ssl: score -= 15; advice.append("Critical: SSL Certificate (HTTPS) is missing.")
        if s_404 > 0: score -= 15; advice.append(f"Broken Links: Found {s_404} dead pages (404 errors).")
        if len(essentials) < 4: score -= 20; advice.append(f"Policy: Missing essential pages. Found {len(essentials)}/5.")
        if banned: score -= 30; advice.append(f"Safety: Prohibited content found: {', '.join(set(banned))}")
        if avg_words < 600: score -= 15; advice.append(f"Content: Low Value Content Risk. Average words: {avg_words}.")
        if loops > 0: score -= 10; advice.append("Technical: Redirect loops detected.")

        return {
            "score": max(0, score),
            "pages_discovered": total_discovered,
            "pages_scanned": len(results),
            "avg_words": avg_words,
            "load_time": round(time.time() - start_time, 2),
            "has_ssl": has_ssl,
            "s_404": s_404,
            "redirect_loops": loops,
            "essentials_count": len(essentials),
            "has_adsense": has_adsense,
            "has_sitemap": has_sitemap,
            "has_robots": has_robots,
            "advice": advice
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
