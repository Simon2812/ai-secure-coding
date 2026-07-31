# Dockerfile_updated — RTX 5070 (Blackwell, sm_120) variant of llm-module/Dockerfile
# Differences from the original:
#   1. CUDA base image bumped 12.1.1 -> 12.8.0 (Blackwell needs CUDA 12.8+)
#   2. PyTorch installed from the cu128 wheel index (default wheels lack sm_120 kernels)
#   3. bitsandbytes forced to the latest release (4-bit on Blackwell needs a recent build)
# Everything else matches the original: same requirements, same api:app on port 8000.

FROM nvidia/cuda:12.8.0-runtime-ubuntu22.04


WORKDIR /app


RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip


# --- Blackwell fix 1: install a CUDA 12.8 (cu128) PyTorch build FIRST ---
# This wheel includes sm_120 kernels. It is not on the default PyPI index,
# so it must come from PyTorch's cu128 index. Installing it before the
# requirements means the unpinned `torch` in requirements.txt is already
# satisfied and pip will not overwrite it with a default-index build.
RUN pip3 install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cu128


COPY requirements.txt .


# Installs the rest (transformers, peft, bitsandbytes, accelerate, fastapi, ...).
# torch is already satisfied by the cu128 build above.
RUN pip3 install \
    --no-cache-dir \
    -r requirements.txt


# --- Blackwell fix 2: ensure the newest bitsandbytes (sm_120 4-bit support) ---
RUN pip3 install --no-cache-dir --upgrade bitsandbytes


COPY . .


EXPOSE 8000


CMD ["python3", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
