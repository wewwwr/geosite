import asyncio
import aiodns
import httpx
import re
import time
import os
import sqlite3
import ipaddress
import tldextract
from contextlib import closing

# --- КОНФИГУРАЦИЯ ---
V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
RU_CIDR_URL = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ru.cidr"

ENABLE_DNS_CHECK = False        # Отключено, чтобы не убивать SNI/CDN домены
ENABLE_OWNER_CHECK = True       # Включено (проверка через RU CIDR / ASN)

CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"
CACHE_DB = ".cache.db"

RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

extract = tldextract.TLDExtract(cache_dir='.tld_cache')

# --- МОДУЛЬ 0: КЭШИРОВАНИЕ ---
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
            cursor.execute("SELECT value, timestamp FROM cache WHERE key=?", (key,))
            row = cursor.fetchone()
            if row and (time.time() - row[1]) < ttl:
                return row[0]
        return None

    def set(self, key, value):
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)",
                             (key, value, time.time()))

cache = LocalCache()

# --- МОДУЛЬ 1: CRAWLER (Дерево V2Fly) ---
class V2FlyCrawler:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=15.0)
        self.visited = set()

    async def fetch_category(self, category):
        if category in self.visited:
            return []
        self.visited.add(category)
        
        cached_data = cache.get(f"v2fly_{category}")
        if cached_data:
            text = cached_data
        else:
            try:
                print(f"  [Crawler] Выкачиваем ветку: {category}")
                resp = await self.client.get(f"{V2FLY_BASE}{category}")
                if resp.status_code != 200:
                    return []
                text = resp.text
                cache.set(f"v2fly_{category}", text)
            except Exception as e:
                print(f"  [Crawler] Ошибка {category}: {e}")
                return []

        rules = []
        for line in text.splitlines():
            line = line.split('#')[0].strip()
            if not line:
                continue
            if line.startswith('include:'):
                sub_cat = line.split('include:')[1].strip()
                rules.extend(await self.fetch_category(sub_cat))
            else:
                rules.append(line)
        return rules

    async def close(self):
        await self.client.aclose()

# --- МОДУЛЬ 2: PARSER & REGEX EXTRACTOR ---
class RuleParser:
    @staticmethod
    def extract_from_regex(rule):
        """Пытается вытащить реальный домен из регулярного выражения."""
        clean_rule = rule.replace('regexp:', '').replace('\\.', '.')
        # Вырезаем спецсимволы регулярок
        clean_rule = re.sub(r'[\^$()|*+?\[\]\\]', ' ', clean_rule)
        # Ищем паттерны, похожие на домен
        matches = re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+', clean_rule)
        domains = set()
        for m in matches:
            ext = extract(m)
            if ext.suffix and ext.domain:
                domains.add(f"{ext.domain}.{ext.suffix}".lower())
        return domains

    @staticmethod
    def clean(raw_rule):
        if raw_rule.startswith('keyword:'):
            return None # Ключевые слова пропускаем, из них нельзя извлечь конкретный домен
            
        domains = set()
        if raw_rule.startswith('regexp:'):
            domains.update(RuleParser.extract_from_regex(raw_rule))
        else:
            raw_rule = raw_rule.replace('full:', '').replace('domain:', '').split('@')[0].strip()
            ext = extract(raw_rule)
            if ext.suffix and ext.domain:
                parsed = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
                domains.add(parsed.lower())
        return domains

# --- МОДУЛЬ 3: OWNER & ASN CHECKER ---
class OwnerChecker:
    def __init__(self):
        self.ru_networks = []
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(300)

    async def load_ru_cidr(self):
        """Загрузка оффлайн-базы российских подсетей (ASN -> CIDR)."""
        cached_cidr = cache.get("ru_cidr")
        if cached_cidr:
            text = cached_cidr
        else:
            print("  [OwnerCheck] Скачивание свежей базы RU CIDR...")
            async with httpx.AsyncClient() as client:
                resp = await client.get(RU_CIDR_URL)
                text = resp.text
                cache.set("ru_cidr", text)
                
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    self.ru_networks.append(ipaddress.IPv4Network(line))
                except ValueError:
                    pass
        print(f"  [OwnerCheck] Загружено {len(self.ru_networks)} RU подсетей.")

    def is_ip_russian(self, ip_str):
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in net for net in self.ru_networks)
        except Exception:
            return False

    async def check_domain(self, domain, valid_set):
        async with self.semaphore:
            # Сначала проверяем кэш DNS/Owner
            cached_res = cache.get(f"owner_{domain}")
            if cached_res == "RU":
                valid_set.add(domain)
                return
            elif cached_res == "FOREIGN":
                return

            try:
                # Резолвим домен в IP
                answers = await self.resolver.query(domain, 'A')
                for record in answers:
                    if self.is_ip_russian(record.host):
                        valid_set.add(domain)
                        cache.set(f"owner_{domain}", "RU")
                        return
                        
                cache.set(f"owner_{domain}", "FOREIGN")
            except Exception:
                # Если домен не резолвится, мы не можем проверить владельца.
                # Можно добавить его в лог "на ручную проверку", но пока пропускаем.
                pass

# --- ОРКЕСТРАТОР ---
async def main():
    start_time = time.time()
    print("=== RU DomainSet Generator V4 ===")

    print("\n1. Запуск Auto-Crawler (сбор дерева v2fly)...")
    crawler = V2FlyCrawler()
    raw_rules = await crawler.fetch_category("category-ru")
    await crawler.close()
    print(f"   Собрано {len(raw_rules)} сырых правил (включая include).")

    print("\n2. Извлечение доменов (tldextract + regex heuristic)...")
    parsed_domains = set()
    for rule in raw_rules:
        domains = RuleParser.clean(rule)
        if domains:
            parsed_domains.update(domains)
    print(f"   Извлечено уникальных доменов: {len(parsed_domains)}")

    print("\n3. Фильтрация национальных зон (.ru, .su)...")
    filtered_domains = {d for d in parsed_domains if not d.endswith(RU_TLDS)}

    # Применяем локальные исключения
    if os.path.exists(EXCLUDE_DOMAINS_FILE):
        with open(EXCLUDE_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            excludes = {RuleParser.clean(line.strip()) for line in f if line.strip()}
            # excludes содержит множества, выравниваем их
            flat_excludes = {d for sublist in excludes if sublist for d in sublist}
            filtered_domains = {d for d in filtered_domains if not any(d == ex or d.endswith('.' + ex) for ex in flat_excludes)}

    # Добавляем свои
    if os.path.exists(CUSTOM_DOMAINS_FILE):
        with open(CUSTOM_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            customs = {RuleParser.clean(line.strip()) for line in f if line.strip()}
            flat_customs = {d for sublist in customs if sublist for d in sublist}
            filtered_domains.update(flat_customs)

    final_domains = filtered_domains

    if ENABLE_OWNER_CHECK:
        print(f"\n4. Оффлайн-проверка владельца по ASN/CIDR ({len(filtered_domains)} доменов)...")
        checker = OwnerChecker()
        await checker.load_ru_cidr()
        
        ru_owned_domains = set()
        tasks = [checker.check_domain(d, ru_owned_domains) for d in filtered_domains]
        await asyncio.gather(*tasks)
        final_domains = ru_owned_domains
        print(f"   Одобрено {len(final_domains)} доменов (принадлежат RU инфраструктуре).")

    if ENABLE_DNS_CHECK:
        print("\n[Optional] 5. DNS Проверка на живучесть...")
        # Логика DNSChecker здесь, если тумблер включен (для твоей задачи он выключен)
        pass 

    print("\n6. Генерация Russia_International.list...")
    sorted_domains = sorted(list(final_domains))
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российского сегмента\n")
        f.write("# Архитектура V4: Auto-Crawl + Regex Parse + ASN/CIDR Check\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего доменов: {len(sorted_domains)}\n\n")
        for domain in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")

    print(f"\n[УСПЕХ] Сохранено {len(sorted_domains)} чистых, проверенных доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
