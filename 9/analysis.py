import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

# Загрузка данных
with open('events.json', 'r') as f:
    data = json.load(f)

# Преобразование в DataFrame
df = pd.DataFrame(data["events"])

# Анализ
print("Всего событий:", len(df))
print("\nРаспределение по сигнатурам:")
print(df['signature'].value_counts())

# Визуализация
plt.figure(figsize=(10, 6))
signature_counts = df['signature'].value_counts()

# Барплот для топ-15 сигнатур
top_n = min(15, len(signature_counts))
ax = signature_counts.head(top_n).plot(kind='barh', color='steelblue')
plt.title(f'Топ-{top_n} сигнатур событий информационной безопасности', fontsize=14)
plt.xlabel('Количество событий')
plt.ylabel('Сигнатура')

# Добавляем значения на столбцы
for i, v in enumerate(signature_counts.head(top_n).values):
    ax.text(v + 0.5, i, str(v), va='center')

plt.tight_layout()
plt.savefig('security_events_distribution.png', dpi=300, bbox_inches='tight')
plt.show()

print("\nГрафик сохранен как 'security_events_distribution.png'")