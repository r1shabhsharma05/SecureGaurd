# FP classifier image (Python 3.12). Build context is ./backend (see
# docker-compose.yml): service.py imports the sibling severity-ranker
# package via a relative path (BASE_DIR/../severity-ranker), so both
# service directories must be present in the image at the same layout.
FROM python:3.12-slim

WORKDIR /app/services/fp-classifier

COPY services/fp-classifier/requirements.txt ./
# Pin pip FIRST: python:3.12-slim bundles whatever pip was current when
# the base image was built, and that version varies between Render's
# cached image and a fresh pull. The --require-hashes install below was
# verified green against pip 26.3 (real install, all 40 packages), so
# pin to exactly that version — no base-image pip drift.
RUN python -m pip install --no-cache-dir pip==26.3
# --require-hashes enforces the pinned hashes in requirements.txt
# (supply-chain fix for unpinned dependencies); the file carries the
# full resolved closure with a hash per package.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY services/fp-classifier/ ./
COPY services/severity-ranker/ ../severity-ranker/

EXPOSE 8001
# Same entrypoint as the hosted classifier service.
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8001"]
