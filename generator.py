import asyncio
import aiodns
import requests
import re
import time
import os

# Основные источники
SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/yandex",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/vk",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/mailru",
]

# Исключаемые национальные зоны
RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

# Локальные файлы для кастомизации
CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"

async def check_domain(domain, resolver, semaphore, valid_domains):
    """Асинхронно проверяет наличие A-записи у домена."""
    async with semaphore:
        try:
            await resolver.query(domain, 'A')
            valid_domains.add(domain)
        except aiodns.error.DNSError:
            pass

def load_local_list(filename):
    """Загружает домены из локального файла, игнорируя комментарии."""
    domains = set()
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].strip().lower()
                if line:
                    domains.add(line)
    return domains

def fetch_and_clean_domains():
    """Собирает домены из источников по ссылкам."""
    raw_domains = set()
    domain_pattern = re.compile(r'^(?:DOMAIN(?:-SUFFIX)?(?:-KEYWORD)?,)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')

    for url in SOURCES:
        print(f"Загрузка из: {url}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                line = line.split('#')[0].strip()
                if not line:
                    continue
                
                match = domain_pattern.match(line)
                if match:
                    domain = match.group(1).lower()
                    if not domain.endswith(RU_TLDS):
                        raw_domains.add(domain)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    return raw_domains

async def main():
    start_time = time.time()
    
    print("1. Сбор доменов из сети...")
    raw_domains = fetch_and_clean_domains()
    
    print("2. Загрузка пользовательских доменов...")
    custom_domains = load_local_list(CUSTOM_DOMAINS_FILE)
    raw_domains.update(custom_domains)
    print(f"Своих доменов добавлено: {len(custom_domains)}")
    
    print("3. Применение списка исключений...")
    exclude_domains = load_local_list(EXCLUDE_DOMAINS_FILE)
    if exclude_domains:
        filtered_domains = set()
        for d in raw_domains:
            # Проверяем, не совпадает ли домен с исключением и не является ли он его поддоменом
            if not any(d == ex or d.endswith('.' + ex) for ex in exclude_domains):
                filtered_domains.add(d)
        raw_domains = filtered_domains
        print(f"Доменов в списке исключений: {len(exclude_domains)}")
        
    print(f"Итого уникальных доменов для проверки: {len(raw_domains)}")
    
    print("4. Проверка существования доменов (DNS Resolve)...")
    resolver = aiodns.DNSResolver()
    valid_domains = set()
    semaphore = asyncio.Semaphore(200)
    
    tasks = [
        check_domain(domain, resolver, semaphore, valid_domains)
        for domain in raw_domains
    ]
    
    await asyncio.gather(*tasks)
    sorted_domains = sorted(list(valid_domains))
    
    print("5. Генерация Russia_International.list...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российских сервисов\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего доменов: {len(sorted_domains)}\n\n")
        
        for domain in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")
            
    print(f"Готово! Сохранено {len(sorted_domains)} рабочих доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())
