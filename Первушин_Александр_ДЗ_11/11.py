import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch  # Добавлен правильный импорт
import seaborn as sns
import json
import re
from collections import Counter
import warnings

warnings.filterwarnings('ignore')

# Настройка стиля для графиков
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (15, 8)

print("=" * 60)
print("АНАЛИЗ ЛОГОВ BOTSV1")
print("=" * 60)

# ==================== ЭТАП 1. ЗАГРУЗКА И ПОДГОТОВКА ДАННЫХ ====================
print("\n[ЭТАП 1] Загрузка и подготовка данных...")

try:
    with open('botsv1.json', 'r', encoding='utf-8') as file:
        data = json.load(file)
    print("✓ Данные успешно загружены")

    df = pd.DataFrame(data)
except FileNotFoundError:
    print("✗ Файл botsv1.json не найден")
    exit()
except json.JSONDecodeError as e:
    print(f"✗ Ошибка при чтении JSON: {e}")
    exit()

print(f"✓ Загружено записей: {len(df)}")
print(f"✓ Колонки: {df.columns.tolist()}")

# Очистка и нормализация данных
print("\nОчистка и нормализация данных...")

# Извлечение данных из колонки result
print("Извлечение данных из колонки result...")
extracted_data = []
for idx, row in df.iterrows():
    if isinstance(row['result'], dict):
        result_dict = row['result']
        base_record = {'preview': row['preview'], 'offset': row['offset']}

        for key, value in result_dict.items():
            if isinstance(value, list):
                if len(value) > 0:
                    if len(value) == 1:
                        base_record[key] = value[0]
                    else:
                        base_record[key] = ', '.join([str(v) for v in value if v is not None])
                else:
                    base_record[key] = None
            else:
                base_record[key] = value

        extracted_data.append(base_record)

df = pd.DataFrame(extracted_data)
print(f"✓ Создано {len(df.columns)} колонок после извлечения")
print(f"✓ Итоговое количество записей: {len(df)}")

# ==================== ЭТАП 2. АНАЛИЗ ДАННЫХ ====================
print("\n" + "=" * 60)
print("[ЭТАП 2] Анализ данных")
print("=" * 60)

# Определяем тип логов
print("\nОпределение типов логов...")

# Проверяем наличие колонок для WinEventLog
event_columns = [col for col in df.columns if 'event' in col.lower() or 'eventcode' in col.lower()]
dns_columns = [col for col in df.columns if 'query' in col.lower() or 'dns' in col.lower()]

print(f"Найдены колонки EventLog: {event_columns}")
print(f"Найдены колонки DNS: {dns_columns}")

# Разделяем логи
win_events = pd.DataFrame()
dns_logs = pd.DataFrame()

if 'eventcode' in df.columns:
    win_events = df.copy()
    win_events['log_type'] = 'WinEventLog'
    win_events['eventid'] = win_events['eventcode']
    print(f"\n✓ Найдено WinEventLog записей: {len(win_events)}")

if len(dns_columns) > 0:
    dns_logs = df.copy()
    dns_logs['log_type'] = 'DNS'
    dns_logs['query'] = dns_logs[dns_columns[0]].astype(str)
    print(f"✓ Найдено DNS записей: {len(dns_logs)}")

# ==================== АНАЛИЗ WINEVENTLOG ====================
print("\n" + "-" * 40)
print("АНАЛИЗ WINEVENTLOG")
print("-" * 40)

if len(win_events) > 0:
    # Очистка eventid
    def clean_eventid(value):
        if pd.isna(value):
            return None
        try:
            return int(float(str(value).strip()))
        except (ValueError, TypeError):
            return None


    win_events['eventid_clean'] = win_events['eventid'].apply(clean_eventid)

    # Расширенный список подозрительных EventID
    suspicious_events = {
        # Аутентификация
        4624: "Успешный вход в систему",
        4625: "⚠️ НЕУДАЧНАЯ ПОПЫТКА ВХОДА",
        4634: "Выход из системы",
        4648: "⚠️ Вход с явными учетными данными",
        4768: "Запрос билета Kerberos",
        4769: "Запрос служебного билета",
        4771: "⚠️ Сбой аутентификации Kerberos",
        4776: "Проверка учетных данных",
        4800: "Блокировка рабочей станции",
        4801: "Разблокировка рабочей станции",

        # Привилегии и доступ
        4672: "⚠️ НАЗНАЧЕНИЕ СПЕЦПРИВИЛЕГИЙ",
        4688: "Создание процесса",
        4697: "⚠️ Установка службы",
        4698: "⚠️ Создание задания",
        4702: "⚠️ Обновление задания",

        # Управление учетными записями
        4720: "⚠️ СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ",
        4722: "⚠️ Включение учетной записи",
        4723: "⚠️ Попытка изменения пароля",
        4724: "⚠️ Попытка сброса пароля",
        4725: "⚠️ Отключение учетной записи",
        4726: "⚠️ Удаление пользователя",
        4728: "⚠️ Добавление в глобальную группу",
        4732: "⚠️ Добавление в локальную группу",
        4738: "⚠️ Изменение пользователя",
        4740: "⚠️ БЛОКИРОВКА УЧЕТНОЙ ЗАПИСИ",

        # Изменения безопасности
        1102: "⚠️ ОЧИСТКА ЖУРНАЛА АУДИТА",
        4616: "⚠️ Изменение системного времени",
        4719: "⚠️ Изменение политики аудита",

        # Сетевые события
        5140: "Доступ к сетевой папке",
        5145: "Проверка доступа к папке",
        5152: "⚠️ Блокировка пакета",
        5156: "Разрешение соединения",
        5157: "⚠️ Блокировка соединения",

        # Active Directory
        5136: "⚠️ Изменение объекта AD",
        5137: "⚠️ Создание объекта AD",
        5141: "⚠️ Удаление объекта AD",

        # Управление данными
        5376: "⚠️ Сохранение учетных данных",
        5377: "⚠️ Восстановление учетных данных",
        5378: "⚠️ Отказ в доступе",
    }

    # Находим подозрительные события
    win_events['is_suspicious'] = win_events['eventid_clean'].isin(suspicious_events.keys())
    win_events['event_description'] = win_events['eventid_clean'].map(suspicious_events)

    # Заполняем описание для обычных событий
    win_events.loc[win_events['event_description'].isna(), 'event_description'] = \
        win_events.loc[win_events['event_description'].isna(), 'eventid_clean'].apply(
            lambda x: f"Обычное событие (ID: {x})" if pd.notna(x) else "Неизвестное событие"
        )

    # Статистика
    print(f"\nВсего событий WinEventLog: {len(win_events)}")
    print(f"Подозрительных событий: {win_events['is_suspicious'].sum()}")
    print(f"Обычных событий: {len(win_events) - win_events['is_suspicious'].sum()}")

    if win_events['is_suspicious'].sum() > 0:
        print(f"\nПроцент подозрительных: {win_events['is_suspicious'].sum() / len(win_events) * 100:.1f}%")

    # Топ-10 подозрительных событий
    win_suspicious_data = win_events[win_events['is_suspicious']]['event_description'].value_counts().head(10)

    print("\nТоп-10 подозрительных событий WinEventLog:")
    for i, (event, count) in enumerate(win_suspicious_data.items(), 1):
        print(f"{i:2d}. {event}: {count}")

    # Все события для сравнения
    win_all_data = win_events['event_description'].value_counts().head(10)
else:
    win_suspicious_data = pd.Series()
    win_all_data = pd.Series()
    print("! Нет данных WinEventLog для анализа")

# ==================== АНАЛИЗ DNS ====================
print("\n" + "-" * 40)
print("АНАЛИЗ DNS ЛОГОВ")
print("-" * 40)

dns_suspicious_data = pd.Series()
dns_suspicious_categories = []

if len(dns_logs) > 0:
    dns_logs['query_clean'] = dns_logs['query'].astype(str).str.lower()

    print(f"\nВсего DNS записей: {len(dns_logs)}")
    print("\nПримеры DNS запросов:")
    for query in dns_logs['query_clean'].head(5).tolist():
        print(f"  • {query}")

    # Определяем подозрительные DNS запросы
    dns_suspicious_categories = []

    # 1. Подозрительные TLD
    suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.download', '.win', '.bid', '.trade', '.info',
                       '.biz']
    for tld in suspicious_tlds:
        pattern = re.escape(tld) + '$'
        matches = dns_logs[dns_logs['query_clean'].str.contains(pattern, na=False, regex=True)].index
        for _ in range(len(matches)):
            dns_suspicious_categories.append(f'⚠️ Подозрительный TLD: {tld}')

    # 2. Длинные поддомены (DGA)
    dns_logs['first_level_len'] = dns_logs['query_clean'].str.split('.').str[0].str.len()
    long_subdomains = dns_logs[dns_logs['first_level_len'] > 15].index
    for _ in range(len(long_subdomains)):
        dns_suspicious_categories.append('⚠️ Длинный поддомен (возможный DGA)')

    # 3. Фишинговые паттерны
    phishing_patterns = ['login', 'secure', 'account', 'verify', 'update', 'bank', 'paypal',
                         'apple', 'microsoft', 'google', 'amazon', 'security', 'confirm', 'signin']
    for pattern in phishing_patterns:
        matches = dns_logs[dns_logs['query_clean'].str.contains(pattern, na=False, regex=False)].index
        for _ in range(len(matches)):
            dns_suspicious_categories.append(f'⚠️ Фишинг-паттерн: "{pattern}"')

    # 4. IP-адреса в доменах
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    ip_matches = dns_logs[dns_logs['query_clean'].str.contains(ip_pattern, na=False, regex=True)].index
    for _ in range(len(ip_matches)):
        dns_suspicious_categories.append('⚠️ IP-адрес в домене')

    # 5. Нестандартные символы
    non_std = r'[^a-zA-Z0-9\.\-]'
    non_std_matches = dns_logs[dns_logs['query_clean'].str.contains(non_std, na=False, regex=True)].index
    for _ in range(len(non_std_matches)):
        dns_suspicious_categories.append('⚠️ Нестандартные символы')

    if dns_suspicious_categories:
        dns_suspicious_data = pd.Series(dns_suspicious_categories).value_counts().head(10)

        print(f"\nНайдено подозрительных DNS запросов: {len(set(dns_suspicious_categories))} категорий")
        print("\nТоп-10 подозрительных DNS запросов:")
        for i, (category, count) in enumerate(dns_suspicious_data.items(), 1):
            print(f"{i:2d}. {category}: {count}")
    else:
        print("\n! Подозрительных DNS запросов не найдено")
else:
    print("\n! DNS логи отсутствуют")

# ==================== ЭТАП 3. ВИЗУАЛИЗАЦИЯ ====================
print("\n" + "=" * 60)
print("[ЭТАП 3] Визуализация топ-10 подозрительных событий")
print("=" * 60)

# Создаем визуализацию
fig = plt.figure(figsize=(20, 12))

# График 1: Топ-10 WinEventLog (все события)
ax1 = plt.subplot(2, 2, 1)
if len(win_all_data) > 0:
    colors1 = ['#ff6b6b' if '⚠️' in str(idx) else '#4ecdc4' for idx in win_all_data.index]
    bars1 = ax1.barh(range(len(win_all_data)), win_all_data.values, color=colors1)
    ax1.set_yticks(range(len(win_all_data)))
    ax1.set_yticklabels([str(idx)[:40] + '...' if len(str(idx)) > 40 else str(idx) for idx in win_all_data.index],
                        fontsize=9)
    ax1.set_xlabel('Количество событий', fontsize=12)
    ax1.set_title('Топ-10 всех событий WinEventLog', fontweight='bold', fontsize=14)

    # Добавляем значения
    for i, (bar, val) in enumerate(zip(bars1, win_all_data.values)):
        ax1.text(val + 0.5, bar.get_y() + bar.get_height() / 2, str(val), va='center', fontsize=9)

    # Легенда
    legend_elements = [
        Patch(facecolor='#ff6b6b', label='⚠️ Подозрительные'),
        Patch(facecolor='#4ecdc4', label='✅ Обычные')
    ]
    ax1.legend(handles=legend_elements, loc='lower right')
else:
    ax1.text(0.5, 0.5, 'Нет данных WinEventLog', ha='center', va='center', fontsize=14, transform=ax1.transAxes)
    ax1.set_title('WinEventLog', fontweight='bold')

# График 2: Топ-10 подозрительных WinEventLog
ax2 = plt.subplot(2, 2, 2)
if len(win_suspicious_data) > 0:
    colors2 = plt.cm.YlOrRd(np.linspace(0.2, 1, len(win_suspicious_data)))
    bars2 = ax2.barh(range(len(win_suspicious_data)), win_suspicious_data.values, color=colors2)
    ax2.set_yticks(range(len(win_suspicious_data)))
    ax2.set_yticklabels(
        [str(idx)[:40] + '...' if len(str(idx)) > 40 else str(idx) for idx in win_suspicious_data.index], fontsize=9)
    ax2.set_xlabel('Количество событий', fontsize=12)
    ax2.set_title('Топ-10 ПОДОЗРИТЕЛЬНЫХ событий WinEventLog', fontweight='bold', fontsize=14, color='darkred')

    # Добавляем значения
    for i, (bar, val) in enumerate(zip(bars2, win_suspicious_data.values)):
        ax2.text(val + 0.5, bar.get_y() + bar.get_height() / 2, str(val), va='center', fontsize=9)
else:
    ax2.text(0.5, 0.5, 'Нет подозрительных событий\nWinEventLog', ha='center', va='center', fontsize=14,
             transform=ax2.transAxes)
    ax2.set_title('Подозрительные WinEventLog', fontweight='bold')

# График 3: Топ-10 подозрительных DNS
ax3 = plt.subplot(2, 2, 3)
if len(dns_suspicious_data) > 0:
    colors3 = plt.cm.YlGnBu(np.linspace(0.2, 1, len(dns_suspicious_data)))
    bars3 = ax3.barh(range(len(dns_suspicious_data)), dns_suspicious_data.values, color=colors3)
    ax3.set_yticks(range(len(dns_suspicious_data)))
    ax3.set_yticklabels(dns_suspicious_data.index, fontsize=9)
    ax3.set_xlabel('Количество запросов', fontsize=12)
    ax3.set_title('Топ-10 ПОДОЗРИТЕЛЬНЫХ DNS запросов', fontweight='bold', fontsize=14, color='darkblue')

    # Добавляем значения
    for i, (bar, val) in enumerate(zip(bars3, dns_suspicious_data.values)):
        ax3.text(val + 0.5, bar.get_y() + bar.get_height() / 2, str(val), va='center', fontsize=9)
else:
    ax3.text(0.5, 0.5, 'Нет подозрительных DNS запросов', ha='center', va='center', fontsize=14,
             transform=ax3.transAxes)
    ax3.set_title('DNS логи', fontweight='bold')

# График 4: Объединенный топ-10
ax4 = plt.subplot(2, 2, 4)

# Собираем все подозрительные события вместе
combined_data = []

if len(win_suspicious_data) > 0:
    for event, count in win_suspicious_data.head(5).items():
        combined_data.append({'event': f'Win: {event[:30]}...', 'count': count, 'type': 'WinEventLog'})

if len(dns_suspicious_data) > 0:
    for category, count in dns_suspicious_data.head(5).items():
        combined_data.append({'event': f'DNS: {category}', 'count': count, 'type': 'DNS'})

if combined_data:
    combined_df = pd.DataFrame(combined_data)
    combined_df = combined_df.sort_values('count', ascending=True)

    colors4 = ['#ff6b6b' if t == 'WinEventLog' else '#4ecdc4' for t in combined_df['type']]
    bars4 = ax4.barh(range(len(combined_df)), combined_df['count'], color=colors4)
    ax4.set_yticks(range(len(combined_df)))
    ax4.set_yticklabels(combined_df['event'], fontsize=9)
    ax4.set_xlabel('Количество', fontsize=12)
    ax4.set_title('Объединенный топ-10 подозрительных событий', fontweight='bold', fontsize=14)

    # Легенда
    legend_elements = [
        Patch(facecolor='#ff6b6b', label='WinEventLog'),
        Patch(facecolor='#4ecdc4', label='DNS')
    ]
    ax4.legend(handles=legend_elements, loc='lower right')

    # Добавляем значения
    for i, (bar, val) in enumerate(zip(bars4, combined_df['count'])):
        ax4.text(val + 0.5, bar.get_y() + bar.get_height() / 2, str(val), va='center', fontsize=9)
else:
    ax4.text(0.5, 0.5, 'Нет данных для\nобъединенного графика', ha='center', va='center', fontsize=14,
             transform=ax4.transAxes)
    ax4.set_title('Объединенный топ-10', fontweight='bold')

plt.tight_layout()
plt.show()

# ==================== ДОПОЛНИТЕЛЬНАЯ СТАТИСТИКА ====================
print("\n" + "=" * 60)
print("ДОПОЛНИТЕЛЬНАЯ СТАТИСТИКА")
print("=" * 60)

# Детальная статистика по WinEventLog
if len(win_events) > 0:
    print("\n📊 WIN EVENT LOG - ДЕТАЛЬНЫЙ АНАЛИЗ")
    print("-" * 40)
    print(f"Всего записей: {len(win_events)}")
    print(f"Уникальных EventID: {win_events['eventid_clean'].nunique()}")

    print("\nРаспределение EventID:")
    event_dist = win_events['eventid_clean'].value_counts().head(15)
    for event_id, count in event_dist.items():
        is_susp = '⚠️' if event_id in suspicious_events else '✅'
        desc = suspicious_events.get(event_id, 'Обычное событие')
        print(f"  {is_susp} EventID {event_id}: {count} раз - {desc}")

# Детальная статистика по DNS
if len(dns_logs) > 0:
    print("\n📊 DNS ЛОГИ - ДЕТАЛЬНЫЙ АНАЛИЗ")
    print("-" * 40)
    print(f"Всего записей: {len(dns_logs)}")
    print(f"Уникальных запросов: {dns_logs['query_clean'].nunique()}")

    print("\nТоп-10 DNS запросов:")
    top_queries = dns_logs['query_clean'].value_counts().head(10)
    for query, count in top_queries.items():
        print(f"  • {query}: {count} раз")

# Общая статистика
print("\n" + "=" * 60)
print("ИТОГОВАЯ СТАТИСТИКА")
print("=" * 60)
print(f"📁 Всего записей в файле: {len(df)}")
print(f"📊 WinEventLog записей: {len(win_events)}")
print(f"🌐 DNS записей: {len(dns_logs)}")
print(
    f"⚠️ Всего подозрительных событий: {win_events['is_suspicious'].sum() if len(win_events) > 0 else 0} + {len(dns_suspicious_categories) if dns_suspicious_categories else 0}")

# Сохраняем результаты
df.to_csv('processed_logs.csv', index=False)
print("\n✓ Обработанные данные сохранены в 'processed_logs.csv'")
print("=" * 60)
print("АНАЛИЗ ЗАВЕРШЕН")
print("=" * 60)