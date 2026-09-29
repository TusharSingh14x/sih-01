FROM rust:1.88-bookworm AS compiler
WORKDIR /source
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY compiler ./compiler
COPY stdlib ./stdlib
COPY agent ./agent
RUN cargo build --release -p jocky-cli

FROM python:3.13-slim-bookworm
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend
COPY blockchain /app/blockchain
COPY --from=compiler /source/target/release/jocky-cli /usr/local/bin/jocky
ENV PYTHONPATH=/app/backend
WORKDIR /app/backend
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
