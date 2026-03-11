import requests
import pandas as pd
import matplotlib.pyplot as plt
import json
import os
from datetime import datetime
import time
from collections import Counter

API_KEYS = {
    'virustotal': 'f7491dd81096fd4dcc749187e1e776d194b59fac602c7f4b68b7d712d95a4ec3',
    'alienvault': 'bdecd96bdabf0a37742dd184d77c04d1808ce7cf1e8f4bd249d33e30307ad22b'
}


class ThreatDetectionSystem:
    def __init__(self):
        self.threats_found = []
        self.logs_data = []
        self.api_data = []

    # Сбор данных
    def collect_data(self):
        print("[1] Начинаем сбор данных...")

        # Имитация логов Suricata
        self.collect_suricata_logs()

        # API VirusTotal
        self.collect_virustotal_data()

        # AlienVault OTX API
        self.collect_alienvault_data()
        print("[1] Сбор данных завершен\n")
    def collect_suricata_logs(self):
        print("  - Загрузка логов Suricata...")

        # Создаем папку для логов
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Имитация логов Suricata
        sample_logs = [
            {"timestamp": "2024-01-15 10:30:25", "src_ip": "192.168.1.100", "dst_ip": "45.33.22.11",
             "alert": "ET MALWARE Known malicious IP", "severity": 1, "protocol": "TCP"},
            {"timestamp": "2024-01-15 10:32:10", "src_ip": "192.168.1.105", "dst_ip": "8.8.8.8",
             "alert": "ET DNS Query for suspicious domain", "severity": 2, "protocol": "DNS"},
            {"timestamp": "2024-01-15 10:35:42", "src_ip": "192.168.1.110", "dst_ip": "185.130.5.23",
             "alert": "ET TROJAN Possible C2 Communication", "severity": 1, "protocol": "HTTP"},
            {"timestamp": "2024-01-15 10:40:15", "src_ip": "192.168.1.120", "dst_ip": "104.16.85.20",
             "alert": "ET POLICY Suspicious DNS Query", "severity": 2, "protocol": "DNS"},
            {"timestamp": "2024-01-15 10:45:30", "src_ip": "192.168.1.130", "dst_ip": "31.13.79.246",
             "alert": "ET MALWARE Known malicious domain", "severity": 1, "protocol": "HTTPS"},
            {"timestamp": "2024-01-15 10:50:22", "src_ip": "192.168.1.140", "dst_ip": "185.130.5.23",
             "alert": "ET MALWARE Repeated connection to malicious IP", "severity": 1, "protocol": "TCP"},
            {"timestamp": "2024-01-15 10:55:18", "src_ip": "192.168.1.150", "dst_ip": "8.8.4.4",
             "alert": "ET DNS Large number of queries", "severity": 2, "protocol": "DNS"},
            {"timestamp": "2024-01-15 11:00:05", "src_ip": "192.168.1.160", "dst_ip": "5.45.76.89",
             "alert": "ET ATTACK Possible brute force attempt", "severity": 1, "protocol": "SSH"},
            {"timestamp": "2024-01-15 11:05:30", "src_ip": "192.168.1.170", "dst_ip": "91.215.140.22",
             "alert": "ET MALWARE Cobalt Strike beacon detected", "severity": 1, "protocol": "HTTP"},
        ]

        # Сохраняем логи в файл
        with open('logs/suricata_logs.json', 'w') as f:
            json.dump(sample_logs, f, indent=2)

        # Загружаем логи
        with open('logs/suricata_logs.json', 'r') as f:
            self.logs_data = json.load(f)
        print(f"    Загружено {len(self.logs_data)} записей логов")
    def collect_virustotal_data(self):
        print("  - Запрос к VirusTotal API...")

        # Имитация ответа от VirusTotal
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 3,
                        "harmless": 42,
                        "undetected": 50
                    },
                    "reputation": -10,
                    "last_analysis_results": [
                        {"engine_name": "Kaspersky", "category": "malicious", "result": "Trojan.Generic"},
                        {"engine_name": "DrWeb", "category": "malicious", "result": "BackDoor"},
                        {"engine_name": "ESET", "category": "suspicious", "result": "MSIL/Spy.Agent"},
                        {"engine_name": "Avast", "category": "malicious", "result": "Win32:Malware-gen"}
                    ],
                    "tags": ["trojan", "backdoor", "ransomware"]
                }
            }
        }
        self.api_data.append({
            'source': 'virustotal',
            'data': vt_response,
            'timestamp': datetime.now().isoformat()
        })
        print("Данные от VirusTotal получены")
    def collect_alienvault_data(self):
        print("  - Запрос к AlienVault OTX API...")

        # Имитация данных об угрозах от AlienVault
        alienvault_response = {
            "pulses": [
                {
                    "id": "otx_pulse_001",
                    "name": "Активная кампания шифровальщиков",
                    "description": "Обнаружена новая кампария ransomware, targeting Russian organizations",
                    "tags": ["ransomware", "c2", "phishing"],
                    "created": "2024-01-15T08:23:45",
                    "threat_score": 85,
                    "malware_families": ["LockBit", "BlackCat"],
                    "indicators": [
                        {"type": "IPv4", "value": "185.130.5.23", "description": "C2 Server"},
                        {"type": "domain", "value": "evil-update.ru", "description": "Malicious domain"},
                        {"type": "URL", "value": "http://evil-update.ru/payload.exe", "description": "Malware download"}
                    ]
                },
                {
                    "id": "otx_pulse_002",
                    "name": "Фишинговая атака на банки",
                    "description": "Massive phishing campaign targeting Russian banking customers",
                    "tags": ["phishing", "banking", "credential-theft"],
                    "created": "2024-01-14T15:12:30",
                    "threat_score": 75,
                    "malware_families": ["Zeus", "TrickBot"],
                    "indicators": [
                        {"type": "domain", "value": "secure-bank24.ru", "description": "Phishing site"},
                        {"type": "email", "value": "support@secure-bank24.ru", "description": "Phishing email"}
                    ]
                },
                {
                    "id": "otx_pulse_003",
                    "name": "DDoS ботнет активность",
                    "description": "New Mirai variant targeting IoT devices in Russia",
                    "tags": ["ddos", "botnet", "iot"],
                    "created": "2024-01-13T22:45:10",
                    "threat_score": 60,
                    "malware_families": ["Mirai", "Gafgyt"],
                    "indicators": [
                        {"type": "IPv4", "value": "45.33.22.11", "description": "C2 Server"},
                        {"type": "IPv4", "value": "104.16.85.20", "description": "Scanning source"}
                    ]
                }
            ]
        }
        self.api_data.append({
            'source': 'alienvault',
            'data': alienvault_response,
            'timestamp': datetime.now().isoformat()
        })
        print("Данные от AlienVault OTX получены")

    # Анализ данных
    def analyze_data(self):
        print("[2] Анализ данных на угрозы...")

        # Анализ логов Suricata
        self.analyze_logs()

        # Анализ данных VirusTotal
        self.analyze_virustotal()

        # Анализ данных AlienVault
        self.analyze_alienvault()
        print(f"[2] Анализ завершен. Найдено угроз: {len(self.threats_found)}\n")
    def analyze_logs(self):
        print("  - Анализ логов Suricata...")

        # Создаем DataFrame для анализа
        df = pd.DataFrame(self.logs_data)

        # Анализируем IP-адреса
        ip_counts = Counter([log['dst_ip'] for log in self.logs_data])

        # Ищем подозрительные паттерны
        for log in self.logs_data:
            # Проверяем severity
            if log['severity'] == 1:
                threat = {
                    'type': 'High Severity Alert',
                    'source': 'Suricata',
                    'details': log['alert'],
                    'ip': log['dst_ip'],
                    'src_ip': log['src_ip'],
                    'protocol': log.get('protocol', 'Unknown'),
                    'timestamp': log['timestamp'],
                    'severity': 'HIGH'
                }
                self.threats_found.append(threat)
                print(f"    ! Найдена угроза: {log['alert']} от {log['src_ip']} к {log['dst_ip']}")

        # Анализируем частые запросы к одному IP
        for ip, count in ip_counts.items():
            if count >= 2:  # Подозрительно много запросов
                threat = {
                    'type': 'Repeated Connections',
                    'source': 'Suricata',
                    'details': f'IP {ip} получил {count} подключений',
                    'ip': ip,
                    'count': count,
                    'severity': 'MEDIUM'
                }
                self.threats_found.append(threat)
                print(f"    ! Подозрительная активность: {count} подключений к {ip}")
    def analyze_virustotal(self):
        print("  - Анализ данных VirusTotal...")
        for vt_data in self.api_data:
            if vt_data['source'] == 'virustotal':
                stats = vt_data['data']['data']['attributes']['last_analysis_stats']
                results = vt_data['data']['data']['attributes']['last_analysis_results']
                if stats['malicious'] > 0:
                    threat = {
                    'type': 'Malicious Object Detected',
                    'source': 'VirusTotal',
                    'details': f'Обнаружено {stats["malicious"]} вредоносных детектов',
                    'malicious_count': stats['malicious'],
                    'suspicious_count': stats['suspicious'],
                    'detections': [r['result'] for r in results if r['category'] == 'malicious'],
                    'severity': 'CRITICAL' if stats['malicious'] > 3 else 'HIGH'
                }
                self.threats_found.append(threat)
                print(f"    ! Обнаружен вредоносный объект (определили {stats['malicious']} антивирусов)")
    def analyze_alienvault(self):
        print("  - Анализ данных AlienVault OTX...")
        for av_data in self.api_data:
            if av_data['source'] == 'alienvault':
                pulses = av_data['data']['pulses']
                for pulse in pulses:

                    # Проверяем threat_score
                    threat_score = pulse['threat_score']
                    threat = {
                        'type': 'Threat Intelligence',
                        'source': 'AlienVault OTX',
                        'details': pulse['description'],
                        'pulse_name': pulse['name'],
                        'threat_score': threat_score,
                        'tags': pulse['tags'],
                        'malware_families': pulse['malware_families'],
                        'indicators': pulse['indicators'],
                        'severity': 'CRITICAL' if threat_score >= 80 else 'HIGH' if threat_score >= 60 else 'MEDIUM'
                    }
                    self.threats_found.append(threat)

                    # Добавляем индикаторы компрометации как отдельные угрозы
                    for indicator in pulse['indicators']:
                        ioc_threat = {
                            'type': f'IoC - {indicator["type"]}',
                            'source': 'AlienVault OTX',
                            'details': indicator['description'],
                            'indicator': indicator['value'],
                            'indicator_type': indicator['type'],
                            'severity': 'HIGH'
                        }
                        self.threats_found.append(ioc_threat)
                    print(f"    ! Обнаружена угроза: {pulse['name']} (оценка: {threat_score})")
                    print(f"      Теги: {', '.join(pulse['tags'])}")

    # Реагирование на угрозы
    def respond_to_threats(self):
        print("[3] Реагирование на угрозы...")
        if not self.threats_found:
            print("  Угроз не обнаружено. Реагирование не требуется.")
            return

        # Группируем угрозы по severity
        threats_by_severity = {}
        for threat in self.threats_found:
            severity = threat['severity']
            if severity not in threats_by_severity:
                threats_by_severity[severity] = []
            threats_by_severity[severity].append(threat)

        # Счетчики для статистики
        blocked_ips = set()
        notifications_sent = 0

        # Реагируем на каждую угрозу
        for severity, threats in threats_by_severity.items():
            print(f"\n  [Обработка угроз уровня {severity}] - {len(threats)} угроз")
            for threat in threats:
                # Имитация блокировки IP
                if 'ip' in threat:
                    ip = threat['ip']
                    if ip not in blocked_ips:
                        print(f"    🔴 БЛОКИРОВКА: IP {ip} заблокирован на файерволе")
                        print(f"       Причина: {threat['details']}")
                        blocked_ips.add(ip)
                    else:
                        print(f"    IP {ip} уже заблокирован")

                # Имитация блокировки индикаторов из AlienVault
                if 'indicator' in threat and threat['indicator_type'] == 'IPv4':
                    indicator = threat['indicator']
                    if indicator not in blocked_ips:
                        print(f"    🔴 БЛОКИРОВКА (по данным разведки): IP {indicator} заблокирован")
                        print(f"       Причина: {threat['details']}")
                        blocked_ips.add(indicator)

                # Имитация уведомления
                self.send_notification(threat)
                notifications_sent += 1

                # Для критических угроз - экстренное реагирование
                if severity == 'CRITICAL':
                    print(f"    🚨 ЭКСТРЕННОЕ РЕАГИРОВАНИЕ: {threat['details']}")
                    print(f"       Создан инцидент #{len(self.threats_found)} в системе SIEM")
        print(f"\n  [3] Реагирование завершено:")
        print(f"      - Заблокировано IP: {len(blocked_ips)}")
        print(f"      - Отправлено уведомлений: {notifications_sent}")
        print()
    def send_notification(self, threat):
        """Имитация отправки уведомления в Telegram/email"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        notification = f"""
        ⚠️ УВЕДОМЛЕНИЕ ОБ УГРОЗЕ [{timestamp}]
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        📋 Тип: {threat['type']}
        📌 Источник: {threat['source']}
        🔍 Детали: {threat['details']}
        ⚡ Уровень: {threat['severity']}
        """

        # Добавляем дополнительную информацию в зависимости от типа угрозы
        if 'ip' in threat:
            notification += f"\n   🌐 IP-адрес: {threat['ip']}"
        if 'protocol' in threat:
            notification += f"\n   📡 Протокол: {threat['protocol']}"
        if 'malware_families' in threat:
            notification += f"\n   🦠 Вредонос: {', '.join(threat['malware_families'])}"
        if 'tags' in threat:
            notification += f"\n   🏷️ Теги: {', '.join(threat['tags'])}"
        notification += "\n   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

        # Сохраняем уведомление в лог
        with open('notifications.log', 'a', encoding='utf-8') as f:
            f.write(notification)

        # Имитация отправки в Telegram (просто вывод в консоль)
        print(f"    📨 Уведомление отправлено в Telegram (тип: {threat['type']})")

    # Формирование отчета и визуализация
    def generate_report(self):
        print("[4] Формирование отчета...")

        # Создаем папку для отчетов
        if not os.path.exists('reports'):
            os.makedirs('reports')

        # Подготавливаем данные для отчета
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_threats': len(self.threats_found),
                'sources_analyzed': {
                    'suricata_logs': len(self.logs_data),
                    'api_calls': len(self.api_data)
                }
            },
            'threats': self.threats_found,
            'statistics': self.calculate_statistics()
        }

        # Сохраняем JSON отчет
        json_filename = f'reports/threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        # Создаем DataFrame для анализа
        df = pd.DataFrame(self.threats_found)

        # Сохраняем в CSV
        csv_filename = f'reports/threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        df.to_csv(csv_filename, index=False, encoding='utf-8')

        # Создаем визуализацию
        self.create_visualization(df)
        print(f"[4] Отчет сохранен:")
        print(f"    - {json_filename}")
        print(f"    - {csv_filename}")
        print(f"    - reports/threat_visualization.png\n")
    def calculate_statistics(self):
        stats = {
            'by_severity': {},
            'by_source': {},
            'by_type': {},
            'unique_ips': set()
        }
        for threat in self.threats_found:
            # По severity
            severity = threat['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # По источнику
            source = threat['source']
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

            # По типу
            threat_type = threat['type']
            stats['by_type'][threat_type] = stats['by_type'].get(threat_type, 0) + 1

            # Уникальные IP
            if 'ip' in threat:
                stats['unique_ips'].add(threat['ip'])

        # Преобразуем set в список для JSON сериализации
        stats['unique_ips'] = list(stats['unique_ips'])
        stats['total_unique_ips'] = len(stats['unique_ips'])
        return stats
    def create_visualization(self, df):
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))

        # График 1: Распределение угроз по severity
        if 'severity' in df.columns:
            severity_counts = df['severity'].value_counts()
            colors = {'CRITICAL': '#8B0000', 'HIGH': '#FF4500', 'MEDIUM': '#FFA500', 'LOW': '#FFFF00'}
            severity_colors = [colors.get(s, '#1E90FF') for s in severity_counts.index]
            bars1 = ax1.bar(severity_counts.index, severity_counts.values, color=severity_colors)
            ax1.set_title('Распределение угроз по уровню опасности', fontsize=12, fontweight='bold')
            ax1.set_xlabel('Уровень опасности')
            ax1.set_ylabel('Количество угроз')

            # Добавляем значения на столбцы
            for bar in bars1:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width() / 2., height,
                         f'{int(height)}', ha='center', va='bottom')

        # График 2: Топ источников угроз
        if 'source' in df.columns:
            source_counts = df['source'].value_counts().head(5)
            colors2 = plt.cm.Set3(range(len(source_counts)))
            bars2 = ax2.bar(source_counts.index, source_counts.values, color=colors2)
            ax2.set_title('Топ-5 источников угроз', fontsize=12, fontweight='bold')
            ax2.set_xlabel('Источник')
            ax2.set_ylabel('Количество')
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
            for bar in bars2:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width() / 2., height,
                         f'{int(height)}', ha='center', va='bottom')

        # График 3: Типы угроз (круговая диаграмма)
        if 'type' in df.columns:
            type_counts = df['type'].value_counts().head(5)
            colors3 = plt.cm.Pastel1(range(len(type_counts)))
            wedges, texts, autotexts = ax3.pie(type_counts.values,
                                               labels=type_counts.index,
                                               autopct='%1.1f%%',
                                               colors=colors3,
                                               textprops={'fontsize': 9})
            ax3.set_title('Топ-5 типов угроз', fontsize=12, fontweight='bold')

            # Настройка текста
            for text in texts:
                text.set_fontsize(8)
            for autotext in autotexts:
                autotext.set_fontsize(8)
                autotext.set_color('white')
        plt.suptitle(f'Анализ угроз безопасности\n{datetime.now().strftime("%d.%m.%Y %H:%M")}',
                     fontsize=14, fontweight='bold')
        plt.tight_layout()

        # Сохраняем график
        plt.savefig('reports/threat_visualization.png', dpi=150, bbox_inches='tight',
                    facecolor='white', edgecolor='none')
        plt.close()
        print("График создан и сохранен")
    def run(self):
        """Запуск всей системы"""
        print("=" * 70)
        print("🚀 ЗАПУСК СИСТЕМЫ ОБНАРУЖЕНИЯ УГРОЗ")
        print("=" * 70 + "\n")
        start_time = time.time()
        self.collect_data()
        self.analyze_data()
        self.respond_to_threats()
        self.generate_report()
        elapsed_time = time.time() - start_time
        print("=" * 70)
        print("✅ РАБОТА СИСТЕМЫ ЗАВЕРШЕНА")
        print("=" * 70)
        print(f"📊 Статистика:")
        print(f"   - Всего обнаружено угроз: {len(self.threats_found)}")
        print(f"   - Время выполнения: {elapsed_time:.2f} сек")
        print(f"   - Создано отчетов: 3")
        print("=" * 70)

# Запуск системы
if __name__ == "__main__":

    # Создаем папки если их нет
    for folder in ['logs', 'reports']:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # Запускаем основную систему с AlienVault
    print("🔍 Используется AlienVault OTX ")
    system = ThreatDetectionSystem()
    system.run()

    # Дополнительно: пример чтения созданных отчетов
    print("\n" + "=" * 70)
    print("ПРИМЕР РАБОТЫ С СОЗДАННЫМИ ОТЧЕТАМИ")
    print("=" * 70)

    # Находим последний JSON отчет
    report_files = [f for f in os.listdir('reports') if f.endswith('.json')]
    if report_files:
        latest_report = max([f for f in report_files],
                            key=lambda x: os.path.getctime(os.path.join('reports', x)))

        # Чтение JSON отчета
        with open(os.path.join('reports', latest_report), 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        print(f"\nАнализ отчета {latest_report}:")
        print(f"   - Всего угроз: {report_data['metadata']['total_threats']}")
        print(f"   - По уровням опасности:")
        for severity, count in report_data['statistics']['by_severity'].items():
            print(f"     * {severity}: {count}")
        print(f"   - Уникальных IP: {report_data['statistics']['total_unique_ips']}")
    print("\n✅ Все файлы успешно созданы:")
    print("   reports/ - папка с отчетами")
    print("   logs/ - папка с логами")
    print("   notifications.log - лог уведомлений")