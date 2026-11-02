# FP classifier image (Python 3.12). Build context is ./backend (see
# docker-compose.yml): service.py imports the sibling severity-ranker
# package via a relative path (BASE_DIR/../severity-ranker), so both
# service directories must be present in the image at the same layout.
FROM python:3.12-slim

WORKDIR /app/services/fp-classifier

COPY services/fp-classifier/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/fp-classifier/ ./
COPY services/severity-ranker/ ../severity-ranker/

EXPOSE 8001
# Same entrypoint as the hosted classifier service.
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8001"]
