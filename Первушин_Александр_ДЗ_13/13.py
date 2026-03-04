import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, Any, Optional

API_KEY = "f7491dd81096fd4dcc749187e1e776d194b59fac602c7f4b68b7d712d95a4ec3"
class VirusTotalAPI:
    """Класс для работы с VirusTotal API"""
    BASE_URL = "https://www.virustotal.com/api/v3"
    def __init__(self, api_key: Optional[str] = None):

        # Приоритет: аргумент -> переменная класса -> переменная окружения
        self.api_key = api_key or API_KEY or os.environ.get('VT_API_KEY')
        if not self.api_key:
            raise ValueError(
                "API ключ не найден. Укажите ключ в переменной API_KEY в коде "
                "или установите переменную окружения VT_API_KEY"
            )

        # Маскируем ключ при выводе (показываем только первые и последние 4 символа)
        masked_key = f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) > 8 else "***"
        print(f" Используется API ключ: {masked_key}")
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/files/{file_hash}"
        try:
            print(f" Запрос к: {url}")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f" Ошибка при запросе к API: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Статус код: {e.response.status_code}")
                print(f"Ответ сервера: {e.response.text}")
                if e.response.status_code == 401:
                    print("\n Ошибка авторизации! Проверьте правильность API ключа.")
                elif e.response.status_code == 404:
                    print("\n Файл с таким хешем не найден в базе VirusTotal.")
                elif e.response.status_code == 429:
                    print("\n Слишком много запросов! Бесплатный API ограничен: 4 запроса в минуту.")
            raise
    def get_scan_status(self, file_hash: str) -> Dict[str, Any]:
        report = self.get_file_report(file_hash)

        # Извлекаем информацию о статусе сканирования
        if 'data' in report and 'attributes' in report['data']:
            attributes = report['data']['attributes']
            scan_status = {
                'file_hash': file_hash,
                'last_analysis_date': attributes.get('last_analysis_date'),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'total_votes': attributes.get('total_votes', {}),
                'popular_threat_classification': attributes.get('popular_threat_classification'),
                'times_submitted': attributes.get('times_submitted'),
                'meaningful_name': attributes.get('meaningful_name'),
                'type_description': attributes.get('type_description'),
                'size': attributes.get('size'),
                'md5': attributes.get('md5'),
                'sha1': attributes.get('sha1'),
                'sha256': attributes.get('sha256'),
                'last_analysis_results': attributes.get('last_analysis_results', {})
            }
            return scan_status
        return {'error': 'Не удалось получить информацию о файле'}
def format_output(data: Dict[str, Any]) -> str:
    if 'error' in data:
        return f"❌ Ошибка: {data['error']}"
    output = []
    output.append("=" * 70)
    output.append(" РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ VIRUSTOTAL")
    output.append("=" * 70)

    # Основная информация
    output.append(f" Файл: {data.get('meaningful_name', 'Неизвестно')}")
    output.append(f" Тип: {data.get('type_description', 'Неизвестно')}")
    output.append(f" Размер: {data.get('size', 0):,} байт ({data.get('size', 0) / 1024:.2f} KB)")
    output.append(f" Проверяемый хеш: {data['file_hash']}")

    # Хеши
    output.append(f" Хеши файла:")
    output.append(f"   MD5:     {data.get('md5', 'N/A')}")
    output.append(f"   SHA-1:   {data.get('sha1', 'N/A')}")
    output.append(f"   SHA-256: {data.get('sha256', 'N/A')}")

    # Статистика обнаружений
    output.append(f" РЕЗУЛЬТАТЫ ПРОВЕРКИ:")
    stats = data.get('last_analysis_stats', {})
    total = sum(stats.values())
    output.append(f"   Всего проверок: {total}")

    # Цветовой вывод для разных категорий
    harmless = stats.get('harmless', 0)
    suspicious = stats.get('suspicious', 0)
    malicious = stats.get('malicious', 0)
    undetected = stats.get('undetected', 0)

    if malicious > 0:
        output.append(f"ВРЕДОНОСНО: {malicious} ({(malicious / total * 100):.1f}%)")
    if suspicious > 0:
        output.append(f"Подозрительно: {suspicious} ({(suspicious / total * 100):.1f}%)")
    output.append(f"Безопасно: {harmless} ({(harmless / total * 100):.1f}%)")
    output.append(f"Не обнаружено: {undetected} ({(undetected / total * 100):.1f}%)")

    # Детальные результаты (топ 10 антивирусов)
    results = data.get('last_analysis_results', {})
    if results:
        output.append(f"ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ (первые 10):")

        # Сортируем: сначала вредоносные, потом подозрительные, потом остальные
        sorted_results = sorted(
            results.items(),
            key=lambda x: (
                0 if x[1].get('category') == 'malicious' else
                1 if x[1].get('category') == 'suspicious' else
                2 if x[1].get('category') == 'harmless' else 3
            )
        )
        for i, (engine, res) in enumerate(sorted_results[:10]):
            category = res.get('category', 'unknown')
            result_text = res.get('result', 'clean')

            # Эмодзи в зависимости от результата
            if category == 'malicious':
                emoji = '🚨'
            elif category == 'suspicious':
                emoji = '⚠️'
            elif category == 'harmless':
                emoji = '✅'
            else:
                emoji = '❓'
            output.append(f"   {emoji} {engine[:20]}: {category} - {result_text}")

    # Дата последнего анализа
    scan_date = data.get('last_analysis_date')
    if scan_date:
        scan_date_str = datetime.fromtimestamp(scan_date).strftime('%Y-%m-%d %H:%M:%S')
        output.append(f"Последний анализ: {scan_date_str}")
    output.append(f"Всего отправлено на проверку: {data.get('times_submitted', 0)} раз")
    output.append("\n" + "=" * 70)
    return "\n".join(output)

def save_to_file(data: Dict[str, Any], filename: str = "virustotal_result.json"):

    # Добавляем временную метку к имени файла
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_with_time = f"virustotal_{timestamp}.json"
    with open(filename_with_time, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"Полные результаты сохранены в файл: {filename_with_time}")

def main():

    # Тестовые хеши
    EXAMPLE_HASHES = {
        'eicar': '44d88612fea8a8f36de82e1278abb02f',  # EICAR тестовый файл (вредоносный)
        'clean': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Пустой файл
        'notepad': '14711bf08e8e37ed7d9f4950d75a767ac990dc5d4fe3c428cbdcdb7426b7c4ef'  # notepad.exe
    }
    print("=" * 70)
    print("VIRUSTOTAL API КЛИЕНТ")
    print("=" * 70)

    # Получаем хеш из аргументов командной строки
    if len(sys.argv) > 1:
        file_hash = sys.argv[1]
        print(f"Проверка файла с хешем: {file_hash}")
    else:

        # Используем тестовый хеш по умолчанию
        file_hash = EXAMPLE_HASHES['eicar']
        print(f"Хеш не указан. Используем тестовый: {file_hash}")
        print("   Для проверки другого файла укажите хеш как аргумент:")
        print(f"   python {sys.argv[0]} <file_hash>")
        print()
    try:
        # Создаем экземпляр API клиента
        vt = VirusTotalAPI()
        print(f"Запрашиваем информацию...")

        # Получаем статус сканирования
        scan_status = vt.get_scan_status(file_hash)

        # Выводим отформатированный результат
        print(format_output(scan_status))

        # Сохраняем полный JSON ответ
        full_report = vt.get_file_report(file_hash)
        save_to_file(full_report)

        # Спрашиваем, хочет ли пользователь увидеть сырой JSON
        print("Показать сырой JSON ответ? (y/n): ", end="")
        response = input().strip().lower()
        if response == 'y' or response == 'yes':
            print("JSON ОТВЕТ:")
            print(json.dumps(full_report, indent=2, ensure_ascii=False))

    except ValueError as e:
        print(f"Ошибка конфигурации: {e}")
        print("Инструкция по настройке:")
        print("1. Получите API ключ на https://www.virustotal.com")
        print("2. Вставьте ключ в переменную API_KEY в коде")
        print("   или установите переменную окружения VT_API_KEY")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Файл с хешем {file_hash} не найден в базе VirusTotal")
        elif e.response.status_code == 401:
            print("Ошибка авторизации. Проверьте правильность API ключа")
        elif e.response.status_code == 429:
            print("Слишком много запросов! Подождите минуту и попробуйте снова.")
        else:
            print(f"HTTP ошибка: {e}")
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}")
        print("Тип ошибки:", type(e).__name__)
if __name__ == "__main__":
    main()