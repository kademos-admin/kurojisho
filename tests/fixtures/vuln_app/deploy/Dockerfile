FROM python:latest
ADD . /app
RUN pip install -r /app/api/requirements.txt
EXPOSE 22
CMD ["python", "/app/api/app.py"]
