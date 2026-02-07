import argparse
import socket
import random
import time
import gzip
import zlib
from io import BytesIO
from urllib.parse import urlparse, parse_qs, unquote
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap, Raw


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path += '?' + parsed.query
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    print(f"\n[+] Отправка запроса:")
    print(f"    URL: {hostname}{path}")
    print(f"    Запрос:\n{http_request_str[:200]}...")

    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None

    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)

    time.sleep(0.1)

    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_request, verbose=False)

    return dest_ip, port, client_sport


def decode_http_body(body, headers):
    """Декодирует тело HTTP-ответа (работает с gzip и deflate)."""
    if not body:
        return body

    content_encoding = None
    for header in headers:
        if header.lower().startswith('content-encoding:'):
            content_encoding = header.split(':', 1)[1].strip().lower()
            break

    try:
        if content_encoding == 'gzip':
            return gzip.decompress(body).decode('utf-8', errors='ignore')
        elif content_encoding == 'deflate':
            return zlib.decompress(body).decode('utf-8', errors='ignore')
        else:
            return body.decode('utf-8', errors='ignore')
    except:
        return body.decode('utf-8', errors='ignore')


def analyze_http_packet(data):
    """Анализирует HTTP-пакет и извлекает информацию."""
    try:
        lines = data.split('\r\n')
        if not lines:
            return None

        # Проверяем, является ли это HTTP
        if not ('HTTP/' in lines[0] or 'GET ' in lines[0] or 'POST ' in lines[0]):
            return None

        analysis = {
            'is_request': 'HTTP/' not in lines[0],
            'method': '',
            'url': '',
            'status': '',
            'headers': [],
            'body': '',
            'parameters': {},
            'cookies': {}
        }

        if analysis['is_request']:
            # Это HTTP запрос
            request_line = lines[0].split()
            if len(request_line) >= 2:
                analysis['method'] = request_line[0]
                analysis['url'] = request_line[1]

                # Извлекаем параметры из URL
                if '?' in analysis['url']:
                    url_parts = analysis['url'].split('?', 1)
                    analysis['url'] = url_parts[0]
                    if len(url_parts) > 1:
                        analysis['parameters'] = parse_qs(url_parts[1])
        else:
            # Это HTTP ответ
            analysis['status'] = lines[0]

        # Извлекаем заголовки
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ': ' in line:
                analysis['headers'].append(line)
                if line.lower().startswith('cookie:'):
                    # Парсим cookies
                    cookies = line.split(':', 1)[1].strip()
                    for cookie in cookies.split(';'):
                        if '=' in cookie:
                            key, value = cookie.strip().split('=', 1)
                            analysis['cookies'][key] = value

        # Извлекаем тело
        if body_start < len(lines):
            body_lines = lines[body_start:]
            analysis['body'] = '\r\n'.join(body_lines)

        return analysis

    except Exception as e:
        print(f"Ошибка анализа HTTP: {e}")
        return None


def packet_callback(packet):
    """Callback функция для обработки перехваченных пакетов."""
    if packet.haslayer(Raw):
        try:
            data = packet[Raw].load.decode('utf-8', errors='ignore')
            analysis = analyze_http_packet(data)

            if analysis:
                print(f"\n{'=' * 60}")
                if analysis['is_request']:
                    print(f"HTTP ЗАПРОС: {analysis['method']} {analysis['url']}")
                    if analysis['parameters']:
                        print(f"Параметры: {analysis['parameters']}")
                else:
                    print(f"HTTP ОТВЕТ: {analysis['status']}")

                print(f"Заголовки ({len(analysis['headers'])}):")
                for header in analysis['headers'][:5]:  # Показываем первые 5 заголовков
                    print(f"  {header}")

                if analysis['body'] and len(analysis['body']) > 0:
                    body_preview = analysis['body'][:200]
                    print(f"Тело (первые 200 символов): {body_preview}")

                # Проверка на XSS payload
                xss_patterns = ['<script>', 'alert(', 'onerror=', 'onload=', 'javascript:']
                for pattern in xss_patterns:
                    if pattern in data.lower():
                        print(f"\n⚠️  ВНИМАНИЕ: Обнаружен XSS паттерн '{pattern}'")
                        break

        except:
            pass


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        print(f"Не удалось разрешить hostname: {hostname}")
        return None

    print(f"\n[+] Начало перехвата трафика для {hostname} ({dest_ip}) на {timeout} секунд...")
    print(f"    Используйте браузер для взаимодействия с сайтом")
    print(f"    Нажмите Ctrl+C для остановки\n")

    # BPF фильтр для захвата трафика
    bpf_filter = f"host {dest_ip} and (port 80 or port 443)"

    try:
        packets = sniff(
            filter=bpf_filter,
            prn=packet_callback,
            timeout=timeout,
            store=True
        )

        print(f"\n[+] Перехвачено пакетов: {len(packets)}")

        if output_file and packets:
            wrpcap(output_file, packets)
            print(f"[+] Трафик сохранен в {output_file}")
            return output_file

        return packets

    except KeyboardInterrupt:
        print("\n[!] Перехват трафика остановлен пользователем")
        if packets and output_file:
            wrpcap(output_file, packets)
            print(f"[+] Трафик сохранен в {output_file}")
        return packets
    except Exception as e:
        print(f"Ошибка перехвата: {e}")
        return None


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return

    http_requests = []
    http_responses = []
    xss_detected = []

    xss_patterns = [
        '<script>', '</script>', 'alert(', 'onerror=', 'onload=',
        'onmouseover=', 'javascript:', 'eval(', 'document.cookie'
    ]

    for pkt in packets:
        if pkt.haslayer(Raw):
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')

                # Проверяем, HTTP ли это
                if 'HTTP/' in data or 'GET ' in data or 'POST ' in data:
                    analysis = analyze_http_packet(data)

                    if analysis:
                        if analysis['is_request']:
                            http_requests.append(analysis)
                        else:
                            http_responses.append(analysis)

                        # Поиск XSS
                        for pattern in xss_patterns:
                            if pattern.lower() in data.lower():
                                xss_info = {
                                    'packet': pkt.summary(),
                                    'pattern': pattern,
                                    'data_preview': data[:300],
                                    'is_request': analysis['is_request']
                                }
                                xss_detected.append(xss_info)
                                break

            except Exception as e:
                continue

    # Вывод результатов анализа
    print(f"\n{'=' * 60}")
    print("РЕЗУЛЬТАТЫ АНАЛИЗА ТРАФИКА")
    print(f"{'=' * 60}")
    print(f"Всего пакетов: {len(packets)}")
    print(f"HTTP запросов: {len(http_requests)}")
    print(f"HTTP ответов: {len(http_responses)}")
    print(f"Обнаружено XSS: {len(xss_detected)}")

    if http_requests:
        print(f"\nПЕРВЫЕ 3 HTTP ЗАПРОСА:")
        for i, req in enumerate(http_requests[:3], 1):
            print(f"\n{i}. {req['method']} {req['url']}")
            if req['parameters']:
                print(f"   Параметры: {req['parameters']}")

    if xss_detected:
        print(f"\n{'!' * 60}")
        print("ОБНАРУЖЕНЫ XSS!")
        print(f"{'!' * 60}")
        for i, xss in enumerate(xss_detected, 1):
            print(f"\n{i}. {'Запрос' if xss['is_request'] else 'Ответ'}")
            print(f"   Паттерн: {xss['pattern']}")
            print(f"   Данные: {xss['data_preview'][:150]}...")

    return {
        'total_packets': len(packets),
        'http_requests': http_requests,
        'http_responses': http_responses,
        'xss_detected': xss_detected
    }


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"[+] Анализ трафика из файла: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        return analyze_packets(packets)
    except Exception as e:
        print(f"Ошибка загрузки pcap файла: {e}")
        return None


def send_xss_payloads(hostname, path, payloads_file=None):
    """Отправляет XSS payloads для тестирования."""
    print(f"[+] Тестирование XSS на {hostname}{path}")

    # Стандартные payloads
    default_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "' onmouseover='alert(\"XSS\")'",
        "\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    ]

    if payloads_file:
        try:
            with open(payloads_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except:
            payloads = default_payloads
            print(f"[!] Не удалось загрузить файл {payloads_file}, использую стандартные payloads")
    else:
        payloads = default_payloads

    results = []

    for i, payload in enumerate(payloads[:10], 1):  # Тестируем первые 10
        print(f"\n[{i}] Тестируем payload: {payload}")

        # Формируем URL с payload
        if '?' in path:
            test_url = f"{path}&test={payload}"
        else:
            test_url = f"{path}?test={payload}"

        # Отправляем запрос
        result = send_http_request(hostname, test_url)
        if result:
            results.append({'payload': payload, 'success': True})
        else:
            results.append({'payload': payload, 'success': False})

        time.sleep(1)  # Пауза между запросами

    print(f"\n[+] Тестирование завершено. Отправлено {len(results)} payloads")
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scary',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
# Отправка HTTP-запроса
python scary.py --send google-gruyere.appspot.com/123456

# Перехват трафика (60 секунд)
python scary.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap

# Анализ сохраненного трафика
python scary.py --analyze traffic.pcap

# Тестирование XSS
python scary.py --send google-gruyere.appspot.com/123456 --xss --payloads payloads.txt
        """
    )

    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )

    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )

    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )

    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )

    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос'
    )

    parser.add_argument(
        '--xss',
        action='store_true',
        help='Протестировать XSS payloads'
    )

    parser.add_argument(
        '--payloads',
        metavar='FILE',
        help='Файл с XSS payloads для тестирования'
    )

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return

        print(f"[+] Отправка HTTP-запроса на {hostname}{path}")

        if args.xss:
            # Тестирование XSS
            send_xss_payloads(hostname, path, args.payloads)
        else:
            # Обычный запрос
            result = send_http_request(hostname, path, args.request)
            if result:
                print("[+] HTTP-запрос отправлен")
            else:
                print("[-] Ошибка при отправке HTTP-запроса")

    # Перехват трафика
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)

    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()