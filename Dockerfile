FROM python:3.9-slim

WORKDIR /app

# Установка Nmap и системных зависимостей
RUN apt-get update && apt-get install -y \
    nmap \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

ENV PYTHONPATH=/app

# Запуск приложения
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]