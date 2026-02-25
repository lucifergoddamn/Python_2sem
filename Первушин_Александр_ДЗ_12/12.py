import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import json
from collections import Counter
import os

# КОНФИГУРАЦИЯ
FILE_PATH = 'dhcp.pcapng'  # УКАЖИТЕ ПУТЬ К ВАШЕМУ ФАЙЛУ

# ФУНКЦИЯ АНАЛИЗА
def analyze_network_capture(file_path):
    """Анализирует сетевой дамп и извлекает ключевые артефакты"""
    print("=" * 60)
    print("НАЧАЛО АНАЛИЗА СЕТЕВОГО ДАМПА")
    print("=" * 60)
    if not os.path.exists(file_path):
        print(f"❌ Файл {file_path} не найден!")
        print("\nДоступные файлы в текущей директории:")
        for file in os.listdir('.'):
            if file.endswith(('.pcap', '.pcapng', '.cap')):
                print(f"  - {file}")
        return None
    print(f"✅ Анализируем файл: {file_path}")

    # Структуры для хранения данных
    dns_queries = []
    ip_connections = []
    try:
        # Открываем файл для чтения
        cap = pyshark.FileCapture(file_path, keep_packets=False)
        packet_count = 0
        for packet in cap:
            packet_count += 1
            packet_time = float(packet.sniff_timestamp)

            # Анализ DNS запросов
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                dns_query = {
                    'time': datetime.fromtimestamp(packet_time).strftime('%H:%M:%S'),
                    'timestamp': packet_time,
                    'query': packet.dns.qry_name,
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                }
                dns_queries.append(dns_query)

            # Анализ IP соединений
            if hasattr(packet, 'ip'):
                connection = {
                    'time': datetime.fromtimestamp(packet_time).strftime('%H:%M:%S'),
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'protocol': packet.highest_layer,
                    'length': int(packet.length) if hasattr(packet, 'length') else 0
                }
                if hasattr(packet, 'tcp'):
                    connection['src_port'] = packet.tcp.srcport
                    connection['dst_port'] = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    connection['src_port'] = packet.udp.srcport
                    connection['dst_port'] = packet.udp.dstport
                ip_connections.append(connection)

            # Прогресс
            if packet_count % 1000 == 0:
                print(f"  ⏳ Обработано {packet_count} пакетов...")
        cap.close()
        print(f"\n✅ Всего обработано пакетов: {packet_count}")
        print(f"✅ Найдено DNS запросов: {len(dns_queries)}")
        print(f"✅ Найдено IP соединений: {len(ip_connections)}")
        return {
            'dns_queries': dns_queries,
            'ip_connections': ip_connections,
            'total_packets': packet_count
        }
    except Exception as e:
        print(f"❌ Ошибка при анализе: {e}")
        return None

# ФУНКЦИЯ ВИЗУАЛИЗАЦИИ
def visualize_results(results):
    """Создает визуализации и сохраняет результаты"""
    print("\n" + "=" * 60)
    print("ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ")
    print("=" * 60)
    if not results:
        print("❌ Нет данных для визуализации")
        return

    # 1. Топ IP адресов
    if results['ip_connections']:
        all_ips = []
        for conn in results['ip_connections']:
            all_ips.append(conn['src_ip'])
            all_ips.append(conn['dst_ip'])
        ip_frequency = Counter(all_ips)
        top_ips = ip_frequency.most_common(10)
        print("\n📊 ТОП-10 АКТИВНЫХ IP АДРЕСОВ:")
        print("-" * 40)
        for i, (ip, count) in enumerate(top_ips, 1):
            print(f"{i:2}. {ip:20} → {count:6} пакетов")

    # 2. DNS запросы
    if results['dns_queries']:
        dns_names = [q['query'] for q in results['dns_queries']]
        dns_frequency = Counter(dns_names)
        top_dns = dns_frequency.most_common(10)
        print("\n📊 ТОП-10 ЗАПРАШИВАЕМЫХ ДОМЕНОВ:")
        print("-" * 40)
        for i, (domain, count) in enumerate(top_dns, 1):
            print(f"{i:2}. {domain[:30]:30} → {count:4} запросов")

        # График DNS запросов по времени
        if len(results['dns_queries']) > 1:
            # Группируем по минутам
            dns_by_minute = {}
            for query in results['dns_queries']:
                minute = query['time'][:5]
                dns_by_minute[minute] = dns_by_minute.get(minute, 0) + 1
            plt.figure(figsize=(12, 5))
            minutes = list(dns_by_minute.keys())
            counts = list(dns_by_minute.values())
            plt.plot(minutes, counts, marker='o', linestyle='-', color='blue', linewidth=2)
            plt.title('Динамика DNS запросов по времени', fontsize=14, pad=15)
            plt.xlabel('Время', fontsize=11)
            plt.ylabel('Количество запросов', fontsize=11)
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig('dns_timeline.png', dpi=100)
            plt.show()
            print("\n✅ График сохранен как 'dns_timeline.png'")

    # 3. Сохранение в файлы
    if results['dns_queries']:
        dns_df = pd.DataFrame(results['dns_queries'])
        dns_df.to_csv('dns_queries.csv', index=False)
        print("\n✅ DNS запросы сохранены в 'dns_queries.csv'")
        with open('dns_queries.json', 'w') as f:
            json.dump(results['dns_queries'][:100], f, indent=2)  # Первые 100 для компактности
        print("✅ DNS запросы сохранены в 'dns_queries.json'")
    if results['ip_connections']:
        ip_df = pd.DataFrame(results['ip_connections'][:500])  # Первые 500
        ip_df.to_csv('ip_connections.csv', index=False)
        print("✅ IP соединения сохранены в 'ip_connections.csv'")

# ФУНКЦИЯ ПОИСКА ПОДОЗРИТЕЛЬНОЙ АКТИВНОСТИ
def find_suspicious(results):
    """Поиск потенциально подозрительных артефактов"""
    print("\n" + "=" * 60)
    print("ПОИСК ПОДОЗРИТЕЛЬНОЙ АКТИВНОСТИ")
    print("=" * 60)
    if not results:
        return
    suspicious_ips = []
    suspicious_domains = []

    # Подозрительные ключевые слова в доменах
    suspicious_keywords = ['malware', 'virus', 'exploit', 'bot', 'c2', 'hack',
                           'trojan', 'ransom', 'phishing', 'evil', 'bad']

    # Проверка DNS
    if results['dns_queries']:
        for query in results['dns_queries']:
            domain = query['query'].lower()
            for keyword in suspicious_keywords:
                if keyword in domain and domain not in suspicious_domains:
                    suspicious_domains.append(domain)
                    print(f"⚠️ Подозрительный домен: {domain}")

    # Поиск аномально активных IP
    if results['ip_connections']:
        ip_counter = Counter([conn['src_ip'] for conn in results['ip_connections']])
        if ip_counter:
            avg = sum(ip_counter.values()) / len(ip_counter)
            threshold = avg * 3
            for ip, count in ip_counter.items():
                if count > threshold and count > 50:
                    suspicious_ips.append(ip)
                    print(f"⚠️ Аномально активный IP: {ip} ({count} соединений)")
    if not suspicious_ips and not suspicious_domains:
        print("✅ Подозрительной активности не обнаружено")

# ОСНОВНАЯ ПРОГРАММА
def main():
    """Главная функция"""
    print("=" * 60)
    print("АНАЛИЗАТОР СЕТЕВОГО ТРАФИКА")
    print("=" * 60)

    # Анализ
    results = analyze_network_capture(FILE_PATH)
    if results:

        # Визуализация
        visualize_results(results)

        # Поиск подозрительной активности
        find_suspicious(results)
        print("\n" + "=" * 60)
        print("✅ АНАЛИЗ ЗАВЕРШЕН УСПЕШНО")
        print("=" * 60)
    else:
        print("\n❌ Анализ не выполнен. Проверьте путь к файлу.")
if __name__ == "__main__":
    main()