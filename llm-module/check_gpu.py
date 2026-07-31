"""
check_gpu.py — RTX 5070 (Blackwell / sm_120) sanity check.

Run this INSIDE the container before the full model load:
    docker run --rm -it --gpus all secure-coding-llm python3 check_gpu.py

It verifies, in order:
  1. torch sees CUDA + the GPU
  2. compute capability (want (12, 0) for the 5070)
  3. a real tensor op runs on the GPU
  4. bitsandbytes 4-bit works  <-- the real go/no-go for this model

Each check prints PASS/FAIL independently, so a failure tells you exactly
which layer is the problem.
"""

def line():
    print("-" * 60)


ok = True

# 1 + 2 + 3: torch / CUDA / GPU compute
line()
try:
    import torch
    print(f"torch version      : {torch.__version__}")
    avail = torch.cuda.is_available()
    print(f"cuda available     : {avail}")
    if not avail:
        print("FAIL: torch cannot see CUDA. Check --gpus all and the driver.")
        ok = False
    else:
        name = torch.cuda.get_device_name(0)
        cap = torch.cuda.get_device_capability(0)
        print(f"gpu                : {name}")
        print(f"compute capability : {cap}   (expect (12, 0) for RTX 5070)")
        # real kernel launch — this is what throws 'no kernel image' if torch
        # lacks sm_120 kernels
        x = torch.randn(1024, 1024, device="cuda")
        y = (x @ x).sum().item()
        print(f"gpu matmul         : PASS  (result={y:.1f})")
        if cap[0] < 12:
            print("NOTE: capability below (12,0) — is this really the 5070?")
except Exception as e:
    print(f"FAIL (torch/cuda): {type(e).__name__}: {e}")
    ok = False

# 4: bitsandbytes 4-bit — the decisive test
line()
try:
    import torch
    import bitsandbytes as bnb
    print(f"bitsandbytes ver   : {bnb.__version__}")
    # Build a 4-bit linear layer, move it to GPU, run a forward pass.
    # This exercises the exact nf4 kernels the model relies on.
    layer = bnb.nn.Linear4bit(
        64, 64, bias=False,
        compute_dtype=torch.float16,
        quant_type="nf4",
    ).cuda()
    inp = torch.randn(2, 64, device="cuda", dtype=torch.float16)
    out = layer(inp)
    torch.cuda.synchronize()
    print(f"4-bit forward      : PASS  (output shape={tuple(out.shape)})")
    print(">>> bitsandbytes 4-bit works on this GPU. The model should load.")
except Exception as e:
    print(f"4-bit forward      : FAIL  ({type(e).__name__}: {e})")
    print(">>> bitsandbytes 4-bit does NOT work on this GPU.")
    print(">>> This is the blocker: try `pip install -U bitsandbytes`, or a")
    print(">>> newer/nightly build with Blackwell (sm_120) support.")
    ok = False

line()
print("OVERALL:", "ALL CHECKS PASSED — good to run the model." if ok
      else "SOMETHING FAILED — see the FAIL line(s) above.")
