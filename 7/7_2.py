import requests
API_KEY = "МОЙ КЛЮЧ" #ключ так получить и не удалось, но запросы принимать должен
BASE_URL = "http://api.openweathermap.org/data/2.5/weather"
def get_weather(city_name):
    params = {         #Параметры запроса
        "q": city_name,
        "appid": API_KEY,
        "units": "metric",  #Для температуры в градусах Цельсия
        "lang": "ru"        #Для описания на русском
    }
    try:
        response = requests.get(BASE_URL, params=params) #Отправляем GET-запрос
        response.raise_for_status()
        data = response.json() #Парсим JSON
        temp = data["main"]["temp"] #Извлекаем нужные данные
        description = data["weather"][0]["description"]
        city = data["name"]
        print(f"Погода в городе {city}:") #Выводим результаты
        print(f"Температура: {temp}°C")
        print(f"Описание: {description.capitalize()}")
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            print("Город не найден. Проверьте название")
        else:
            print(f"Ошибка HTTP: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе к API: {e}")
    except KeyError:
        print("Некорректный ответ от API")
if __name__ == "__main__":
    city = input("Введите название города: ") #Запрос названия города у пользователя
    get_weather(city)