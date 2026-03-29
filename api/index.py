from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
import random
import concurrent.futures

app = FastAPI()

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9'
}

def analyze_single_page(url):
    try:
        time.sleep(random.uniform(0.1, 0.3))
        res = requests.get(url, headers=HEADERS, timeout=8)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text().lower()
            return {
                "status": res.status_code,
                "words": len(text.split()),
                "text": text,
                "loop": len(res.history) >= 3
            }
        return {"status": res.status_code, "words": 0, "text": "", "loop": False}
    except:
        return {"status": 0, "words": 0, "text": "", "loop": False}

@app.get("/api/audit")
def audit(url: str = Query(...)):
    start_time = time.time()
    try:
        # Step 1: Homepage fetch
        home_res = requests.get(url, headers=HEADERS, timeout=10)
        home_soup = BeautifulSoup(home_res.text, 'html.parser')
        
        links = home_soup.find_all('a', href=True)
        internal_urls = list(set([urljoin(url, a['href']).split('#')[0] for a in links 
                                 if urlparse(urljoin(url, a['href'])).netloc == urlparse(url).netloc]))
        
        # Taking top 30 for safety/speed on Vercel
        scan_list = internal_urls[:30]
        if url not in scan_list: scan_list.insert(0, url)

        # Step 2: Multi-threaded Scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            pages_results = list(executor.map(analyze_single_page, scan_list))

        # Step 3: Calculation
        valid_pages = [p for p in pages_results if p['words'] > 0]
        avg_words = sum(p['words'] for p in valid_pages) // len(valid_pages) if valid_pages else 0
        s_404 = sum(1 for p in pages_results if p['status'] >= 400)
        redirect_loops = sum(1 for p in pages_results if p['loop'])
        combined_text = " ".join([p['text'] for p in pages_results])
        
        essentials = [ep for ep in ["privacy", "contact", "about", "disclaimer", "terms"] if any(ep in u.lower() for u in internal_urls)]
        banned = [w for w in ["hack", "cracked", "mod apk", "adult", "casino", "porn"] if w in combined_text]
        
        score = 100
        advice = []
        if not url.startswith("https"): score -= 15; advice.append("Install SSL (HTTPS).")
        if s_404 > 0: score -= 15; advice.append(f"Fix {s_404} broken (404) links.")
        if len(essentials) < 4: score -= 20; advice.append("Add missing Policy pages (Privacy, About, Terms).")
        if banned: score -= 30; advice.append(f"Remove prohibited keywords: {', '.join(set(banned))}")
        if avg_words < 500: score -= 15; advice.append(f"Thin Content (Avg {avg_words} words). Increase depth.")

        return JSONResponse({
            "score": max(0, score),
            "load_time": round(time.time() - start_time, 2),
            "pages_scanned": len(pages_results),
            "avg_words": avg_words,
            "s_404": s_404,
            "redirect_loops": redirect_loops,
            "essentials_found": len(essentials),
            "has_ssl": url.startswith("https"),
            "advice": advice
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
