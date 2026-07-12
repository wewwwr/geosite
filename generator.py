import asyncio
import httpx
import re
import time
import os
import json
import tldextract
from collections import defaultdict

# ==========================================
# --- КОНФИГУРАЦИЯ КАСТОМНЫХ ДОМЕНОВ ---
# ==========================================

# 1. Твои кастомные домены (ДОБАВЛЯТЬ СЮДА)
# Эти домены будут добавлены в самое начало списка и проигнорируют любые фильтры/исключения
CUSTOM_DOMAINS = [
    "ru",
    "su",
    "рф",
]

# 2. Исключения (ДОБАВЛЯТЬ СЮДА)
# Эти домены будут принудительно удалены из итогового списка
EXCLUDE_DOMAINS = [
    "bad-domain.com",
    "ads-.org",
]

# ==========================================
# --- КОНФИГУРАЦИЯ ИСТОЧНИКОВ ---
# ==========================================
SOURCES_CONFIG = [
    {
        "name": "V2Fly",
        "type": "v2fly_tree",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",
        "entry_point": "category-ru"
    },
    {
        "name": "MetaCubeX_RU",
        "type": "plain",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ru.list"
    },
    {
        "name": "MetaCubeX_Category_RU",
        "type": "plain",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.list"
    },
    {
        "name": "BlackMatrix",
        "type": "plain",
        "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Russia/Russia.list"
    }
]

RU_TLDS = ('.ru', '.рф', '.su', '.xn--p1ai')

STATS = {
    "sources": defaultdict(int),
    "excluded": 0,
    "total_approved": 0
}

# Кэш tldextract сохраняется между запусками GitHub Actions
extract = tldextract.TLDExtract(cache_dir='.tld_cache')

class RuleParser:
    @staticmethod
    def get_registered_domain(domain_str):
        """Извлекает строго корневой домен (registrable domain)"""
        ext = extract(domain_str)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return None

    @staticmethod
    def extract_from_regex(rule):
        """Эвристика для вытаскивания доменов из регулярных выражений"""
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
                else: return set()
                    
            raw_rule = raw_rule.replace('full:', '').replace('domain:', '').replace('+', '').split('@')[0].strip()
            raw_rule = raw_rule.replace("'", "").replace('"', "")
            
            rd = RuleParser.get_registered_domain(raw_rule)
            if rd: domains.add(rd)
        return domains

class CrawlerEngine:
    def __init__(self):
        self.client = httpx.AsyncClient(http2=True, timeout=10.0)

    async def fetch(self, url):
        try:
            resp = await self.client.get(url)
            if resp.status_code == 200:
                return resp.text
            else:
                print(f"  [SKIPPED] {url} (Статус: {resp.status_code})")
        except Exception as e:
            print(f"  [WARN] Ошибка соединения: {url} -> {e}")
        return ""

    async def crawl_v2fly_tree(self, base_url, category, visited):
        if category in visited: return set()
        visited.add(category)
        
        text = await self.fetch(f"{base_url}{category}")
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
        print(f"-> Парсинг: {source_conf['name']}")
        if source_conf['type'] == 'v2fly_tree':
            return await self.crawl_v2fly_tree(source_conf['url'], source_conf['entry_point'], set())
        elif source_conf['type'] == 'plain':
            text = await self.fetch(source_conf['url'])
            rules = set()
            for line in text.splitlines():
                rules.update(RuleParser.clean(line))
            return rules
        return set()

    async def close(self):
        await self.client.aclose()

async def main():
    start_time = time.time()
    print("=== Запуск RU DomainSet Aggregator ===")

    # 1. Подготовка встроенных кастомных списков
    processed_custom_domains = set()
    for item in CUSTOM_DOMAINS:
        processed_custom_domains.update(RuleParser.clean(item))
    STATS["sources"]["Custom"] = len(processed_custom_domains)

    exclude_set = set()
    for item in EXCLUDE_DOMAINS:
        exclude_set.update(RuleParser.clean(item))

    # 2. Сбор из источников
    all_fetched_domains = set()
    crawler = CrawlerEngine()
    for conf in SOURCES_CONFIG:
        domains = await crawler.run_source(conf)
        STATS["sources"][conf['name']] = len(domains)
        all_fetched_domains.update(domains)
    await crawler.close()

    print(f"\nВсего собрано уникальных доменов из сетей до фильтрации: {len(all_fetched_domains)}")

    # 3. Фильтрация исключений и RU-зон (только для собранных из сети)
    final_auto_domains = set()
    for dom in all_fetched_domains:
        # Пропускаем, если домен уже есть в твоих кастомных (чтобы не было дублей ниже)
        if dom in processed_custom_domains:
            continue
            
        # Отсекаем национальные зоны
        if dom.endswith(RU_TLDS):
            STATS["excluded"] += 1
            continue
            
        # Строгая проверка на пользовательские исключения
        if any(dom == ex or dom.endswith('.' + ex) for ex in exclude_set):
            STATS["excluded"] += 1
            continue
            
        final_auto_domains.add(dom)

    STATS["total_approved"] = len(processed_custom_domains) + len(final_auto_domains)

    # 4. Генерация файлов
    sorted_custom = sorted(list(processed_custom_domains))
    sorted_auto = sorted(list(final_auto_domains))

    with open("Russia_International.list", "w", encoding="utf-8") as f:
        f.write("# Зеркало международных доменов российского сегмента\n")
        f.write("# Источники: V2Fly (category-ru), MetaCubeX, BlackMatrix\n")
        f.write(f"# Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Всего уникальных доменов: {STATS['total_approved']}\n\n")
        
        # СНАЧАЛА пишем кастомные домены, чтобы они были в топе
        if sorted_custom:
            f.write("# --- Пользовательские домены (Custom) ---\n")
            for domain in sorted_custom:
                f.write(f"DOMAIN-SUFFIX,{domain}\n")
            f.write("\n# --- Автоматически собранные домены ---\n")
            
        # ЗАТЕМ все остальные
        for domain in sorted_auto:
            f.write(f"DOMAIN-SUFFIX,{domain}\n")

    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(STATS, f, indent=4)

    print(f"\n[УСПЕХ] Сохранено {STATS['total_approved']} доменов (из них кастомных: {len(sorted_custom)}).")
    print(f"Отброшено (.ru или исключения): {STATS['excluded']}.")
    print(f"Время выполнения: {round(time.time() - start_time, 2)} сек.")

if __name__ == "__main__":
    import sys
    if sys.version_info[0] == 3 and sys.version_info[1] >= 8 and sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
