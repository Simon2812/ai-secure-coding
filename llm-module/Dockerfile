FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04


WORKDIR /app


RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g ts-node typescript \
    && rm -rf /var/lib/apt/lists/*


COPY llm-module/requirements.txt /app/llm-module/requirements.txt


RUN pip3 install \
    --no-cache-dir \
    -r /app/llm-module/requirements.txt


COPY secure-assist/package*.json /app/secure-assist/


WORKDIR /app/secure-assist


RUN npm install --legacy-peer-deps


COPY secure-assist /app/secure-assist
COPY llm-module /app/llm-module


WORKDIR /app/llm-module


EXPOSE 8000


CMD ["python3", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
