import asyncio
import aiodns
import httpx
import re
import time
import os
import tldextract

# --- КОНФИГУРАЦИЯ ---
V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"
UNSUPPORTED_LOG = "unsupported_rules.log"

# Расширенные категории ру-сегмента
V2FLY_CATEGORIES = [
    "category-ru", "category-bank-ru", "category-ecommerce-ru", 
    "category-gov-ru", "category-media-ru", "category-games-ru", 
    "category-travel-ru", "category-finance-ru", "category-social-ru",
    "yandex", "vk", "mailru", "kaspersky", "sberbank", "tinkoff",
    "alfa-bank", "ozon", "wildberries", "avito", "rostelecom", "mts", "megafon"
]

GLOBAL_EXCLUDES = {
    'google.com', 'apple.com', 'microsoft.com', 'cloudflare.com', 'amazon.com',
    'github.com', 'youtube.com', 'netflix.com', 'akamai.net', 'icq.com'
}

# Инициализация tldextract (он сам кэширует суффиксы TLD)
extract = tldextract.TLDExtract(cache_dir='.tld_cache')


# --- МОДУЛИ ПАЙПЛАЙНА ---

class Fetcher:
    """Асинхронная загрузка списков через HTTP/2."""
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=15.0)
        self.visited_v2fly = set()
        self.unsupported_rules = set()

    async def fetch_v2fly_recursive(self, category):
        if category in self.visited_v2fly:
            return []
        
        self.visited_v2fly.add(category)
        url = f"{V2FLY_BASE}{category}"
        domains = []
        
        try:
            response = await self.client.get(url)
            if response.status_code != 200:
                return []
                
            lines = response.text.splitlines()
            for line in lines:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                    
                if line.startswith('include:'):
                    sub_cat = line.split('include:')[1].strip()
                    domains.extend(await self.fetch_v2fly_recursive(sub_cat))
                elif line.startswith(('regexp:', 'keyword:')):
                    self.unsupported_rules.add(line)
                else:
                    domains.append(line)
        except Exception as e:
            print(f"[-] Ошибка загрузки {category}: {e}")
            
        return domains

    async def close(self):
        await self.client.aclose()


class Parser:
    """Очистка и валидация доменов через tldextract."""
    @staticmethod
    def clean(raw_domain):
        # Очистка атрибутов v2fly (@cn, @ads и т.д.)
        raw_domain = raw_domain.replace('full:', '').replace('domain:', '').split('@')[0].strip()
        
        # Парсинг Shadowrocket/Clash форматов
        if ',' in raw_domain:
            parts = raw_domain.split(',')
            if parts[0].strip().upper() in ('DOMAIN-SUFFIX', 'DOMAIN', 'HOST-SUFFIX', 'HOST'):
                raw_domain = parts[1].strip()
            else:
                return None
                
        # Валидация через tldextract (отсекает кривые строки, оставляет валидные субдомены и TLD, включая xn--)
        ext = extract(raw_domain)
        if ext.suffix and ext.domain:
            # Восстанавливаем домен. ext.fqdn не используем, чтобы не добавить лишнего.
            parsed = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
            return parsed.lower()
        return None


class FilterRU:
    """Фильтрация национальных зон и глобальных/пользовательских исключений."""
    @staticmethod
    def process(domains, excludes):
        filtered = set()
        for d in domains:
            if d.endswith(RU_TLDS):
                continue
            if any(d == ex or d.endswith('.' + ex) for ex in excludes):
                continue
            filtered.add(d)
        return filtered


class DNSChecker:
    """Умная асинхронная проверка с фоллбэком A -> AAAA -> CNAME."""
    def __init__(self, concurrency=300):
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.alive_domains = set()

    async def check(self, domain):
        async with self.semaphore:
            # Проверяем последовательно A, AAAA, CNAME. Если хоть что-то есть — домен жив.
            for record_type in ['A', 'AAAA', 'CNAME']:
                try:
                    await self.resolver.query(domain, record_type)
                    self.alive_domains.add(domain)
                    return
                except aiodns.error.DNSError:
                    continue
                except Exception:
                    continue

    async def run(self, domains):
        tasks = [self.check(d) for d in domains]
        await asyncio.gather(*tasks)
        return sorted(list(self.alive_domains))


# --- ГЛАВНЫЙ ОРКЕСТРАТОР ---

async def main():
    start_time = time.time()
    
    print("1. [Fetcher] Сбор баз...")
    fetcher = Fetcher()
    raw_domains = []
    
    # Запускаем сбор категорий асинхронно
    tasks = [fetcher.fetch_v2fly_recursive(cat) for cat in V2FLY_CATEGORIES]
    results = await asyncio.gather(*tasks)
    for res in results:
        raw_domains.extend(res)
        
    await fetcher.close()
    
    # Логируем неподдерживаемые правила
    if fetcher.unsupported_rules:
        with open(UNSUPPORTED_LOG, "w", encoding="utf-8") as f:
            f.write("\n".join(fetcher.unsupported_rules))
        print(f"   -> Пропущено {len(fetcher.unsupported_rules)} keyword/regexp правил. Сохранено в {UNSUPPORTED_LOG}")

    print(f"2. [Parser] Валидация {len(raw_domains)} строк через tldextract...")
    parsed_domains = set()
    for d in raw_domains:
        clean_d = Parser.clean(d)
        if clean_d:
            parsed_domains.add(clean_d)

    print("3. [FilterRU] Применение правил исключений...")
    # Собираем пользовательские исключения
    user_excludes = set()
    if os.path.exists(EXCLUDE_DOMAINS_FILE):
        with open(EXCLUDE_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            user_excludes = {Parser.clean(line) for line in f if Parser.clean(line)}
    
    all_excludes = GLOBAL_EXCLUDES.union(user_excludes)
    filtered_domains = FilterRU.process(parsed_domains, all_excludes)

    # Подмешиваем кастомные домены пользователя
    if os.path.exists(CUSTOM_DOMAINS_FILE):
        with open(CUSTOM_DOMAINS_FILE, 'r', encoding='utf-8') as f:
            customs = {Parser.clean(line) for line in f if Parser.clean(line)}
            filtered_domains.update(customs)

    print(f"   -> Уникальных международных доменов для DNS-проверки: {len(filtered_domains)}")

    print("4. [DNSChecker] Проверка A / AAAA / CNAME...")
    checker = DNSChecker(concurrency=400)
    final_domains = await checker.run(filtered_domains)

    print("5. [Output] Генерация .list файла...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российского сегмента\n")
        f.write("# Генератор V3 (tldextract + A/AAAA/CNAME Check)\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего живых доменов: {len(final_domains)}\n\n")
        for domain in final_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")

    print(f"\n[УСПЕХ] Сохранено {len(final_domains)} валидных доменов.")
    print(f"Время выполнения: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
