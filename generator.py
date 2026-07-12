import asyncio
import aiodns
import requests
import re
import time
import os

V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"

# Жесткий встроенный фильтр от ложных срабатываний (зарубежные гиганты, CDN, адалт)
GLOBAL_EXCLUDES = {
    'adobe.com', 'pornhub.com', 'google.com', 'apple.com', 'microsoft.com',
    'cloudflare.com', 'akamai.net', 'amazon.com', 'aws.amazon.com', 'cloudfront.net',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'youtube.com',
    'netflix.com', 'spotify.com', 'github.com', 'yahoo.com', 'bing.com',
    'xvideos.com', 'xnxx.com', 'phncdn.com', 'windows.com', 'office.com',
    'apple-dns.net', 'icloud.com', 'whatsapp.com', 'telegram.org'
}

# Прямые курируемые списки (без грязных ASN-сканеров)
DIRECT_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list",
]

# Точечные категории V2Fly для глубокого сканирования
V2FLY_CATEGORIES = [
    "category-ru", "yandex", "vk", "mailru", "kaspersky", 
    "sberbank", "tinkoff", "alfa-bank", "ozon", "wildberries"
]

def fetch_v2fly_recursive(file_name, visited=None):
    if visited is None:
        visited = set()
    
    if file_name in visited:
        return []
    
    visited.add(file_name)
    url = V2FLY_BASE + file_name
    print(f"  [v2fly] Сбор: {file_name}")
    domains = []
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
            
        for line in response.text.splitlines():
            line = line.split('#')[0].strip()
            if not line:
                continue
                
            if line.startswith('include:'):
                sub_file = line.split('include:')[1].strip()
                domains.extend(fetch_v2fly_recursive(sub_file, visited))
            else:
                domain = extract_domain(line)
                if domain:
                    domains.append(domain)
    except Exception as e:
        print(f"  [v2fly] Ошибка при загрузке {file_name}: {e}")
        
    return domains

def extract_domain(line):
    line = line.split('#')[0].strip()
    if not line:
        return None
        
    if ',' in line:
        parts = line.split(',')
        if parts[0].strip().upper() in ('DOMAIN-SUFFIX', 'DOMAIN', 'HOST-SUFFIX', 'HOST'):
            line = parts[1].strip()
        else:
            return None
            
    line = line.replace('full:', '').replace('domain:', '').split('@')[0].strip()
    
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
        return line.lower()
    return None

def load_local_list(filename):
    domains = set()
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                d = extract_domain(line)
                if d:
                    domains.add(d)
    return domains

def is_excluded(domain, exclude_set):
    """Проверяет, входит ли домен или его поддомен в список исключений."""
    return any(domain == ex or domain.endswith('.' + ex) for ex in exclude_set)

def fetch_and_clean_domains():
    raw_domains = set()
    
    print("-> 1. Сбор точечных баз V2Fly...")
    for cat in V2FLY_CATEGORIES:
        raw_domains.update(fetch_v2fly_recursive(cat))
    
    print("-> 2. Загрузка курируемых листов...")
    for url in DIRECT_SOURCES:
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    d = extract_domain(line)
                    if d:
                        raw_domains.add(d)
        except Exception as e:
            print(f"  Ошибка загрузки {url}: {e}")
            
    return raw_domains

async def check_domain(domain, resolver, semaphore, valid_domains):
    async with semaphore:
        try:
            await resolver.query(domain, 'A')
            valid_domains.add(domain)
        except Exception:
            pass

async def main():
    start_time = time.time()
    
    raw_domains = fetch_and_clean_domains()
    
    print("-> 3. Фильтрация и подключение локальных списков...")
    # 1. Отсекаем чисто российские зоны (.ru, .рф)
    raw_domains = {d for d in raw_domains if not d.endswith(RU_TLDS)}
    
    # 2. Применяем жесткий встроенный фильтр
    raw_domains = {d for d in raw_domains if not is_excluded(d, GLOBAL_EXCLUDES)}
    
    # 3. Применяем пользовательский фильтр из exclude_domains.txt
    user_excludes = load_local_list(EXCLUDE_DOMAINS_FILE)
    if user_excludes:
        raw_domains = {d for d in raw_domains if not is_excluded(d, user_excludes)}
        
    # 4. Добавляем пользовательские домены
    custom_domains = load_local_list(CUSTOM_DOMAINS_FILE)
    raw_domains.update(custom_domains)
        
    print(f"\nИтого доменов отправлено на DNS-проверку: {len(raw_domains)}")
    
    print("-> 4. Массовая DNS-проверка (отсеивание мертвых доменов)...")
    resolver = aiodns.DNSResolver()
    valid_domains = set()
    semaphore = asyncio.Semaphore(300) 
    
    tasks = [check_domain(d, resolver, semaphore, valid_domains) for d in raw_domains]
    await asyncio.gather(*tasks)
    
    sorted_domains = sorted(list(valid_domains))
    
    print("-> 5. Генерация Russia_International.list...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российских сервисов\n")
        f.write("# Очищено от глобальных CDN и мусора\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего живых доменов: {len(sorted_domains)}\n\n")
        for domain in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")
            
    print(f"\nГотово! Сохранено {len(sorted_domains)} чистых рабочих доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
