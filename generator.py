import asyncio
import httpx
import re
import time
import os
import json
import sqlite3
import tldextract
from contextlib import closing
from collections import defaultdict

# --- КОНФИГУРАЦИЯ ИСТОЧНИКОВ ---
WEIGHT_THRESHOLD = 100

SOURCES_CONFIG = [
    {
        "name": "V2Fly",
        "type": "v2fly_tree",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",
        "entry_point": "category-ru",
        "weight": 100
    },
    {
        "name": "MetaCubeX",
        "type": "plain",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ru.list",
        "weight": 80
    },
    {
        "name": "Loyalsoldier",
        "type": "plain",
        # Для примера берем прямой текстовый исходник от Loyalsoldier (yandex/mailru и тд)
        "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "weight": 70
    },
    {
        "name": "BlackMatrix",
        "type": "plain",
        "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list",
        "weight": 60
    }
]

CUSTOM_WEIGHT = 500

RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')
CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"
CACHE_DB = ".cache.db"

# Инициализация tldextract
extract = tldextract.TLDExtract(cache_dir='.tld_cache')

# --- КЭШ ---
class LocalCache:
    def __init__(self, db_path=CACHE_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute('''CREATE TABLE IF NOT EXISTS cache
                                (key TEXT PRIMARY KEY, value TEXT, timestamp REAL)''')

    def get(self, key, ttl=86400):
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM cache WHERE key=? AND (? - timestamp) < ?", (key, time.time(), ttl))
            row = cursor.fetchone()
            return row[0] if row else None

    def set(self, key, value):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)", (key, value, time.time()))

cache = LocalCache()

# --- ПАРСЕР И НОРМАЛИЗАТОР ---
class RuleParser:
    @staticmethod
    def get_registered_domain(domain_str):
        """Возвращает строго корневой домен (registrable domain). api.vk.com -> vk.com"""
        ext = extract(domain_str)
        if ext.registered_domain:
            return ext.registered_domain.lower()
        return None

    @staticmethod
    def extract_from_regex(rule):
        # Очистка от сложных regex-конструкций вроде (?:^|\.)
        clean_rule = rule.replace('regexp:', '').replace('\\.', '.')
        clean_rule = re.sub(r'(?:\(\?\:\^\|\\\.|\^|\\b|\$)', ' ', clean_rule)
        clean_rule = re.sub(r'[\(\)|*+?\[\]\\]', ' ', clean_rule)
        
        matches = re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+', clean_rule)
        domains = set()
        for m in matches:
            rd = RuleParser.get_registered_domain(m)
            if rd: domains.add(rd)
        return domains

    @staticmethod
    def clean(raw_rule):
        raw_rule = raw_rule.split('#')[0].strip()
        if not raw_rule or raw_rule.startswith('keyword:'):
            return set()
            
        domains = set()
        if raw_rule.startswith('regexp:'):
            domains.update(RuleParser.extract_from_regex(raw_rule))
        else:
            if ',' in raw_rule:
                parts = raw_rule.split(',')
                if parts[0].strip().upper() in ('DOMAIN-SUFFIX', 'DOMAIN'):
                    raw_rule = parts[1].strip()
                else:
                    return set()
                    
            raw_rule = raw_rule.replace('full:', '').replace('domain:', '').replace('+', '').split('@')[0].strip()
            raw_rule = raw_rule.replace("'", "").replace('"', "")
            
            rd = RuleParser.get_registered_domain(raw_rule)
            if rd: domains.add(rd)
        return domains

# --- ДВИЖОК СБОРА ---
class CrawlerEngine:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=15.0)

    async def fetch(self, url, cache_key):
        cached = cache.get(cache_key)
        if cached: return cached
        try:
            resp = await self.client.get(url)
            if resp.status_code == 200:
                cache.set(cache_key, resp.text)
                return resp.text
        except Exception as e:
            print(f"  [-] Ошибка: {url} -> {e}")
        return ""

    async def crawl_v2fly_tree(self, base_url, category, visited):
        if category in visited: return set()
        visited.add(category)
        
        text = await self.fetch(f"{base_url}{category}", f"v2fly_{category}")
        rules = set()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('include:'):
                sub_cat = line.split('include:')[1].strip()
                rules.update(await self.crawl_v2fly_tree(base_url, sub_cat, visited))
            else:
                rules.update(RuleParser.clean(line))
        return rules

    async def run_source(self, source_conf):
        print(f"  [>] Парсинг источника: {source_conf['name']} (Вес: {source_conf['weight']})")
        if source_conf['type'] == 'v2fly_tree':
            return await self.crawl_v2fly_tree(source_conf['url'], source_conf['entry_point'], set())
        elif source_conf['type'] == 'plain':
            text = await self.fetch(source_conf['url'], f"plain_{source_conf['name']}")
            rules = set()
            for line in text.splitlines():
                rules.update(RuleParser.clean(line))
            return rules
        return set()

    async def close(self):
        await self.client.aclose()

# --- RDAP CHECKER ---
class RDAPChecker:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=10.0)
        self.semaphore = asyncio.Semaphore(10)

    async def is_russian(self, domain):
        cached = cache.get(f"rdap_{domain}", ttl=2592000)
        if cached == 'RU': return True
        if cached == 'FOREIGN': return False

        async with self.semaphore:
            try:
                resp = await self.client.get(f"https://rdap.org/domain/{domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Тотальный поиск паттернов по всему дампу JSON
                    dump = json.dumps(data).lower()
                    
                    # Ищем маркеры RU-сегмента (страна, город, юрлицо)
                    markers = [
                        '"country": "ru"', '"country":"ru"', '"cc": "ru"', '"cc":"ru"',
                        'russian federation', 'moscow', 'saint petersburg', 'yandex llc'
                    ]
                    
                    if any(marker in dump for marker in markers):
                        cache.set(f"rdap_{domain}", 'RU')
                        return True
            except Exception:
                pass
                
        cache.set(f"rdap_{domain}", 'FOREIGN')
        return False

    async def close(self):
        await self.client.aclose()

# --- ОРКЕСТРАТОР ---
async def main():
    start_time = time.time()
    print("=== RU DomainSet Generator V6 (Root Domain + RDAP JSON) ===")

    domain_weights = defaultdict(int)

    # 1. ЗАПУСК ИСТОЧНИКОВ ИЗ КОНФИГА
    crawler = CrawlerEngine()
    for conf in SOURCES_CONFIG:
        domains = await crawler.run_source(conf)
        for d in domains:
            domain_weights[d] += conf['weight']
    await crawler.close()

    # Добавляем локальные whitelist домены
    if os.path.exists(CUSTOM_DOMAINS_FILE):
        print(f"  [>] Парсинг источника: Local Custom (Вес: {CUSTOM_WEIGHT})")
        with open(CUSTOM_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                for d in RuleParser.clean(line):
                    domain_weights[d] += CUSTOM_WEIGHT

    # 2. ФИЛЬТРАЦИЯ .RU И ИСКЛЮЧЕНИЙ
    print("\n2. Очистка и фильтрация...")
    exclude_set = set()
    if os.path.exists(EXCLUDE_DOMAINS_FILE):
        with open(EXCLUDE_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                exclude_set.update(RuleParser.clean(line))

    candidate_domains = {}
    for dom, weight in domain_weights.items():
        if dom.endswith(RU_TLDS): continue
        if dom in exclude_set: continue
        candidate_domains[dom] = weight

    # 3. АНАЛИЗ ВЕСОВ
    final_domains = set()
    grey_zone = set()

    for dom, weight in candidate_domains.items():
        if weight >= WEIGHT_THRESHOLD:
            final_domains.add(dom)
        else:
            grey_zone.add(dom)

    print(f"   Зеленая зона (Вес >= {WEIGHT_THRESHOLD}): {len(final_domains)} доменов.")
    print(f"   Серая зона (Требует RDAP): {len(grey_zone)} доменов.")

    # 4. RDAP ПРОВЕРКА СЕРОЙ ЗОНЫ
    if grey_zone:
        print("\n4. Выполнение RDAP-проверки...")
        rdap = RDAPChecker()
        
        async def verify_and_add(d):
            if await rdap.is_russian(d):
                final_domains.add(d)

        tasks = [verify_and_add(d) for d in grey_zone]
        await asyncio.gather(*tasks)
        await rdap.close()

    # 5. ГЕНЕРАЦИЯ
    sorted_domains = sorted(list(final_domains))
    
    print("\n5. Запись Russia_International.list...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российского сегмента\n")
        f.write("# Архитектура V6 (Root Domain Configurable Pipeline)\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего уникальных доменов: {len(sorted_domains)}\n\n")
        
        for domain in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")

    print(f"\n[УСПЕХ] Сохранено {len(sorted_domains)} чистых корневых доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
