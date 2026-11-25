FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Main.py auth.py streamlit_app.py ./

EXPOSE 8000 8501

CMD ["python", "-m", "uvicorn", "Main:app", "--host", "0.0.0.0", "--port", "8000"]
