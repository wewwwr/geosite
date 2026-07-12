import asyncio
import httpx
import re
import time
import os
import sqlite3
import tldextract
from contextlib import closing
from collections import defaultdict

# --- КОНФИГУРАЦИЯ ---
WEIGHT_THRESHOLD = 10

# Веса источников
WEIGHTS = {
    'v2fly': 10,
    'metacubex': 8,
    'blackmatrix7': 7,
    'loyalsoldier': 7,
    'custom': 20
}

RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')
CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"
CACHE_DB = ".cache.db"

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

# --- ПАРСЕР ---
class RuleParser:
    @staticmethod
    def extract_from_regex(rule):
        clean_rule = rule.replace('regexp:', '').replace('\\.', '.')
        clean_rule = re.sub(r'[\^$()|*+?\[\]\\]', ' ', clean_rule)
        matches = re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+', clean_rule)
        domains = set()
        for m in matches:
            ext = extract(m)
            if ext.suffix and ext.domain:
                domains.add(f"{ext.domain}.{ext.suffix}".lower())
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
            # Парсинг .list / yaml / clash / v2ray
            if ',' in raw_rule:
                parts = raw_rule.split(',')
                if parts[0].strip().upper() in ('DOMAIN-SUFFIX', 'DOMAIN'):
                    raw_rule = parts[1].strip()
                else:
                    return set()
                    
            raw_rule = raw_rule.replace('full:', '').replace('domain:', '').replace('+', '').split('@')[0].strip()
            # Убираем кавычки из yaml если есть
            raw_rule = raw_rule.replace("'", "").replace('"', "")
            
            ext = extract(raw_rule)
            if ext.suffix and ext.domain:
                parsed = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
                domains.add(parsed.lower())
        return domains

# --- МОДУЛИ ИСТОЧНИКОВ ---
class SourceCrawler:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=15.0)

    async def fetch(self, url, cache_key):
        cached = cache.get(cache_key)
        if cached:
            return cached
        try:
            resp = await self.client.get(url)
            if resp.status_code == 200:
                cache.set(cache_key, resp.text)
                return resp.text
        except Exception as e:
            print(f"  [-] Ошибка загрузки {url}: {e}")
        return ""

    async def close(self):
        await self.client.aclose()

class V2Fly(SourceCrawler):
    def __init__(self):
        super().__init__()
        self.visited = set()
        self.base_url = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

    async def crawl(self, category="category-ru"):
        if category in self.visited:
            return set()
        self.visited.add(category)
        
        text = await self.fetch(f"{self.base_url}{category}", f"v2fly_{category}")
        rules = set()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('include:'):
                sub_cat = line.split('include:')[1].strip()
                rules.update(await self.crawl(sub_cat))
            else:
                rules.update(RuleParser.clean(line))
        return rules

class BlackMatrix(SourceCrawler):
    async def crawl(self):
        url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list"
        text = await self.fetch(url, "blackmatrix_ru")
        rules = set()
        for line in text.splitlines():
            rules.update(RuleParser.clean(line))
        return rules

# --- RDAP CHECKER (Фоллбэк для серой зоны) ---
class RDAPChecker:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=10.0)
        self.semaphore = asyncio.Semaphore(10) # Строгий лимит для RDAP API

    async def is_russian(self, domain):
        # Проверяем кэш (храним RDAP 30 дней)
        cached = cache.get(f"rdap_{domain}", ttl=2592000)
        if cached == 'RU': return True
        if cached == 'FOREIGN': return False

        # Если не tld, а субдомен, достаем корень
        ext = extract(domain)
        root_domain = f"{ext.domain}.{ext.suffix}"

        async with self.semaphore:
            try:
                # Используем публичный RDAP bootstrap
                resp = await self.client.get(f"https://rdap.org/domain/{root_domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    # Ищем маркеры RU в entities или country
                    is_ru = False
                    for entity in data.get('entities', []):
                        for address in entity.get('vcardArray', [[]])[1]:
                            if isinstance(address, list) and 'ru' in [str(x).lower() for x in address]:
                                is_ru = True
                                break
                    
                    if is_ru:
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
    print("=== RU DomainSet Generator V5 (Consensus & Weight System) ===")

    # Словарь для суммирования весов: {domain: total_weight}
    domain_weights = defaultdict(int)

    # 1. СБОР ИЗ ИСТОЧНИКОВ
    print("\n1. Запуск распределенного сбора...")
    
    # V2Fly
    v2fly = V2Fly()
    v2fly_domains = await v2fly.crawl("category-ru")
    await v2fly.close()
    for d in v2fly_domains: domain_weights[d] += WEIGHTS['v2fly']
    print(f"   [V2Fly] Собрано: {len(v2fly_domains)}")

    # BlackMatrix7
    bm7 = BlackMatrix()
    bm7_domains = await bm7.crawl()
    await bm7.close()
    for d in bm7_domains: domain_weights[d] += WEIGHTS['blackmatrix7']
    print(f"   [BlackMatrix7] Собрано: {len(bm7_domains)}")

    # MetaCubeX / Loyalsoldier добавляются аналогично...
    
    # Custom Whitelist
    if os.path.exists(CUSTOM_DOMAINS_FILE):
        with open(CUSTOM_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                for d in RuleParser.clean(line):
                    domain_weights[d] += WEIGHTS['custom']

    # 2. ФИЛЬТРАЦИЯ
    print("\n2. Фильтрация и дедупликация...")
    # Применяем пользовательские исключения (жесткое удаление)
    exclude_set = set()
    if os.path.exists(EXCLUDE_DOMAINS_FILE):
        with open(EXCLUDE_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                exclude_set.update(RuleParser.clean(line))

    candidate_domains = {}
    for dom, weight in domain_weights.items():
        if dom.endswith(RU_TLDS):
            continue
        # Строгая дедупликация и удаление исключенных
        if not any(dom == ex or dom.endswith('.' + ex) for ex in exclude_set):
            candidate_domains[dom] = weight

    # 3. АНАЛИЗ ВЕСОВ И СЕРОЙ ЗОНЫ
    final_domains = set()
    grey_zone = set()

    for dom, weight in candidate_domains.items():
        if weight >= WEIGHT_THRESHOLD:
            final_domains.add(dom)
        else:
            grey_zone.add(dom)

    print(f"   Зеленая зона (вес >= {WEIGHT_THRESHOLD}): {len(final_domains)} доменов.")
    print(f"   Серая зона (недостаточно веса): {len(grey_zone)} доменов.")

    # 4. RDAP ПРОВЕРКА СЕРОЙ ЗОНЫ
    if grey_zone:
        print("\n4. RDAP-проверка владельцев серой зоны...")
        rdap = RDAPChecker()
        
        async def verify_and_add(d):
            if await rdap.is_russian(d):
                final_domains.add(d)

        # Обрабатываем асинхронно, но батчами, чтобы не положить rdap.org
        tasks = [verify_and_add(d) for d in grey_zone]
        await asyncio.gather(*tasks)
        await rdap.close()

    # 5. ГЕНЕРАЦИЯ
    # Сортировка для аккуратности
    sorted_domains = sorted(list(final_domains))
    
    print("\n5. Запись Russia_International.list...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российского сегмента\n")
        f.write("# Архитектура V5: Consensus Weight System + RDAP\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего уникальных доменов: {len(sorted_domains)}\n\n")
        
        for domain in sorted_domains:
            # Генерация строгого, валидного синтаксиса для Shadowrocket без дублей и лишних параметров
            f.write(f"DOMAIN-SUFFIX,{domain}\n")

    print(f"\n[УСПЕХ] Сохранено {len(sorted_domains)} чистых, проверенных доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
