import asyncio
import aiodns
import requests
import re
import time
import os

# Базовый URL для v2fly (репозиторий со всеми правилами)
V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

# Исключаемые национальные зоны (нас интересуют только международные .com, .net, .io и тд)
RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

CUSTOM_DOMAINS_FILE = "custom_domains.txt"
EXCLUDE_DOMAINS_FILE = "exclude_domains.txt"

# Прямые источники огромных списков (собираются комьюнити на базе ASN, BGP и сертификатов)
DIRECT_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list",
    # itdoginfo — гигантский агрегатор доменов, хостящихся на IP-адресах РФ
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst"
]

def fetch_v2fly_recursive(file_name, visited=None):
    """Рекурсивно выкачивает все подкатегории (банки, маркетплейсы, хостинги) из базы v2fly."""
    if visited is None:
        visited = set()
    
    if file_name in visited:
        return []
    
    visited.add(file_name)
    url = V2FLY_BASE + file_name
    print(f"  [v2fly] Выкачиваем ветку: {file_name}")
    domains = []
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
            
        for line in response.text.splitlines():
            line = line.split('#')[0].strip() # Убираем комментарии
            if not line:
                continue
                
            # Если строка ссылается на другой список (например, include:sberbank) — идем внутрь
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
    """Умный экстрактор доменов, который понимает форматы Surge, Clash, Shadowrocket и V2Ray."""
    line = line.split('#')[0].strip()
    if not line:
        return None
        
    # Формат Shadowrocket/Clash: DOMAIN-SUFFIX,yandex.com,DIRECT
    if ',' in line:
        parts = line.split(',')
        if parts[0].strip().upper() in ('DOMAIN-SUFFIX', 'DOMAIN', 'HOST-SUFFIX', 'HOST'):
            line = parts[1].strip()
        else:
            return None
            
    # Формат v2fly: full:yandex.com или domain:yandex.com
    line = line.replace('full:', '').replace('domain:', '')
    # Убираем атрибуты вроде @cn
    line = line.split('@')[0].strip()
    
    # Строгая проверка, что на выходе получился чистый домен
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
        return line.lower()
    return None

def load_local_list(filename):
    """Читает локальные файлы пользователя."""
    domains = set()
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                d = extract_domain(line)
                if d:
                    domains.add(d)
    return domains

def fetch_and_clean_domains():
    """Сбор всей базы воедино."""
    raw_domains = set()
    
    print("-> 1. Загрузка дерева v2fly (банки, госсектор, IT-компании, ритейл)...")
    v2fly_domains = fetch_v2fly_recursive("category-ru")
    raw_domains.update(v2fly_domains)
    
    print("-> 2. Загрузка агрегированных дампов (сети провайдеров, ASN)...")
    for url in DIRECT_SOURCES:
        print(f"  Парсинг: {url.split('/')[-1]}")
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    d = extract_domain(line)
                    if d:
                        raw_domains.add(d)
        except Exception as e:
            print(f"  Ошибка загрузки: {e}")
            
    print(f"\nВсего собрано доменов до фильтрации: {len(raw_domains)}")
    # Отсекаем чисто российские зоны
    international = {d for d in raw_domains if not d.endswith(RU_TLDS)}
    return international

async def check_domain(domain, resolver, semaphore, valid_domains):
    """Проверяет, жив ли домен в реальности."""
    async with semaphore:
        try:
            await resolver.query(domain, 'A')
            valid_domains.add(domain)
        except Exception:
            pass # Если домен мертвый (устарел, отозван), мы его просто забываем

async def main():
    start_time = time.time()
    
    raw_domains = fetch_and_clean_domains()
    
    print("-> 3. Подключение ваших локальных списков...")
    custom_domains = load_local_list(CUSTOM_DOMAINS_FILE)
    raw_domains.update(custom_domains)
    
    exclude_domains = load_local_list(EXCLUDE_DOMAINS_FILE)
    if exclude_domains:
        filtered = set()
        for d in raw_domains:
            # Удаляем как точное совпадение, так и все поддомены исключений
            if not any(d == ex or d.endswith('.' + ex) for ex in exclude_domains):
                filtered.add(d)
        raw_domains = filtered
        
    print(f"\nИтого уникальных МЕЖДУНАРОДНЫХ доменов для проверки: {len(raw_domains)}")
    
    print("-> 4. Массовая DNS-проверка (отсеивание мусора)...")
    resolver = aiodns.DNSResolver()
    valid_domains = set()
    # 300 одновременных подключений, чтобы проверить десятки тысяч доменов за пару минут
    semaphore = asyncio.Semaphore(300) 
    
    tasks = [check_domain(d, resolver, semaphore, valid_domains) for d in raw_domains]
    await asyncio.gather(*tasks)
    
    sorted_domains = sorted(list(valid_domains))
    
    print("-> 5. Генерация Russia_International.list...")
    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российских сервисов\n")
        f.write("# Источники: v2fly, BlackMatrix, itdoginfo (ASN/CIDR)\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего живых доменов: {len(sorted_domains)}\n\n")
        for domain in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")
            
    print(f"\nГотово! Сохранено {len(sorted_domains)} рабочих доменов.")
    print(f"Затрачено времени: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
