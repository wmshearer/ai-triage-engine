# Phase 2 — Measured LLM Inference Latency (Ollama, local GPU)

Status: MEASURED (not estimated). Produced 2026-08-18.

## 1. Environment

- Host GPU: NVIDIA GeForce RTX 3080 Laptop GPU, 7.8 GiB VRAM (8192 MiB reported by `nvidia-smi`)
- Ollama server: `ollama serve`, already running on `http://localhost:11434`, `OLLAMA_NUM_PARALLEL=1` (confirmed from server startup log — requests are served strictly serially, no concurrent decoding)
- Model: `qwen2.5:7b-instruct-q4_K_M` (7.6B params, Q4_K_M quantization, GGUF, 4.4GB on disk / 4,683,087,332 bytes reported by `/api/tags`)
- Model install: already present at start of this run — `/api/tags` listed it and `du -sh ~/.ollama/models` showed 4.4G. No pull was required in this session (a prior attempt evidently succeeded — DNS issues described in the task brief were not encountered).

### GPU fit / offload

From the ollama server log (`llama_model_loader` / `load_tensors` lines):

```
n_layer = 28 (+1 output layer = 29 total)
load_tensors: offloading output layer to GPU
load_tensors: offloading 27 repeating layers to GPU
load_tensors: offloaded 29/29 layers to GPU
load_tensors: CUDA0 model buffer size = 4168.09 MiB
llama_kv_cache: CUDA0 KV buffer size = 224.00 MiB (4096-cell ctx)
sched_reserve: CUDA0 compute buffer size = 136.01 MiB
```

**All 29/29 layers are offloaded to GPU. No CPU spill.** The model fits fully within the 8GB card at both 4096 and 8192 context lengths.

`nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader`:
- Idle (before model load): `382 MiB, 8192 MiB`
- With model loaded (steady state, after B/C runs at num_ctx=8192): `5470 MiB, 8192 MiB` (~5.1GB attributable to the model + KV cache + compute buffers)

Confirmed trap noted in the task brief: the server log shows `msg="vram-based default context" total_vram="7.8 GiB" default_num_ctx=4096` — Ollama's automatic default is 4096 tokens on this card. This would silently truncate a ~1200-token prompt + 300-token completion pair (1364 prompt tokens alone was measured — see below). `"options": {"num_ctx": 8192}` was set explicitly on conditions B and C to avoid this.

## 2. Methodology

All calls via `POST /api/generate`, `"stream": false`, against `qwen2.5:7b-instruct-q4_K_M`. Timing figures used throughout are the **nanosecond fields from the API response** (`total_duration`, `load_duration`, `prompt_eval_count`, `prompt_eval_duration`, `eval_count`, `eval_duration`), not wall-clock, per the task brief. Decode throughput = `eval_count / (eval_duration / 1e9)`.

- **Condition A — short prompt.** A condensed SOC alert summary/triage prompt. `num_predict: 100`. Default `num_ctx` (4096) — not overridden since the prompt fits comfortably. Actual measured `prompt_eval_count = 366` tokens (my char-count estimate of ~200 was low; Qwen's tokenizer runs denser on this technical/log-heavy text than plain English).
- **Condition B — realistic single-alert triage prompt.** A full SOC alert with EDR detection, network telemetry, prior-alert history, identity context, and environment context (see prompt text below), asking for verdict / ATT&CK technique / confidence / reasoning as free text. `"options": {"num_ctx": 8192}`, `num_predict: 300`. Actual measured `prompt_eval_count = 1364` tokens (above the 1200 target, confirming the num_ctx=8192 override was necessary — at the default 4096 ctx, 1364 prompt + 300 output would still have fit, but a larger real-world prompt would not have; the override is the correct standing configuration regardless).
- **Condition C — same prompt as B, structured output.** Identical prompt to B, `"options": {"num_ctx": 8192}`, `num_predict: 300`, plus `"format"` set to a JSON Schema requiring an object with `verdict` (enum: benign/suspicious/malicious), `attack_technique` (string), `confidence` (number), `reasoning` (string) — grammar-constrained decoding.
- **Trials:** 3 per condition. Per the task brief, the first trial of the *whole benchmark run* should be discarded as cold-start-skewed and reported separately. In practice the true cold model-load (weights from disk into VRAM) happened in a standalone warm-up call made *before* the timed run (see §4) — so none of the 9 timed trials in `results.json` carry that full cold-load cost. All 3 A/B/C trials are therefore included in the medians below. A related but distinct reload cost was observed on B trial 1 (context-length reload, not weight load) — flagged explicitly in §4 and excluded from B's median calculation reasoning (though its total_duration is still shown in the raw table; the median of 3 is robust to this one outlier).
- Prompt/schema files used are preserved at `/tmp/claude-1000/-home-kali-director/55824f36-a4ad-424d-acf2-90fc6b39f83a/scratchpad/{prompt_a.txt,prompt_b.txt,schema.json,bench.py,results.json}`.

### Exact schema used for condition C

```json
{
  "type": "object",
  "properties": {
    "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
    "attack_technique": {"type": "string"},
    "confidence": {"type": "number"},
    "reasoning": {"type": "string"}
  },
  "required": ["verdict", "attack_technique", "confidence", "reasoning"]
}
```

## 3. Raw per-trial results

| Condition | Trial | total_duration (s) | load_duration (s) | prompt_eval_count | prompt_eval_duration (s) | eval_count | eval_duration (s) | decode tok/s |
|---|---|---|---|---|---|---|---|---|
| A_short | 1 | 1.566 | 0.129 | 366 | 0.128 | 100 | 1.292 | 77.43 |
| A_short | 2 | 1.434 | 0.132 | 366 | 0.012 | 100 | 1.286 | 77.75 |
| A_short | 3 | 1.439 | 0.137 | 366 | 0.012 | 100 | 1.287 | 77.71 |
| B_triage | 1 | 7.180 | 2.788 | 1364 | 0.469 | 300 | 3.916 | 76.62 |
| B_triage | 2 | 4.110 | 0.166 | 1364 | 0.014 | 300 | 3.923 | 76.48 |
| B_triage | 3 | 4.134 | 0.167 | 1364 | 0.013 | 300 | 3.946 | 76.03 |
| C_triage_structured | 1 | 4.253 | 0.155 | 1364 | 0.029 | 300 | 4.061 | 73.87 |
| C_triage_structured | 2 | 4.235 | 0.202 | 1364 | 0.025 | 300 | 4.000 | 74.99 |
| C_triage_structured | 3 | 2.203 | 0.197 | 1364 | 0.026 | 139 | 1.973 | 70.45 |

Note on C trial 3: the model emitted a complete, well-formed JSON object and stopped naturally at 139 output tokens (schema satisfied) rather than running to the 300-token cap — this is expected/correct behavior for grammar-constrained decoding on a small schema, not a measurement error. It is included in the raw table for transparency but is a genuinely shorter completion, not a directly comparable "300-token" data point.

## 4. Cold-start cost

Two distinct reload events were observed and are reported separately, since they are different phenomena:

1. **True cold start (model weights, disk → VRAM).** Measured via a standalone warm-up call made before the timed benchmark run (`/tmp/.../scratchpad/warmup.json`): `total_duration = 2.094s`, of which `load_duration = 1.997s`. This is the cost paid the first time the model is invoked after the ollama server starts (or after it's been evicted from the `OLLAMA_KEEP_ALIVE` window, default 5 minutes).
2. **Context-length reload (runner restart on ctx change, VRAM → VRAM).** Observed on B_triage trial 1: `load_duration = 2.788s`, versus ~0.16-0.20s on all other B/C trials. This happens because the model runner had been serving condition A at the default `num_ctx=4096`; switching to `num_ctx=8192` for condition B forced Ollama to spin up a new runner process. This cost is paid once per context-length change, not per call — all subsequent B and C calls (same 8192 ctx) show normal ~0.15-0.2s load_duration (session/KV-cache bookkeeping only, not a real reload).

**Practical implication:** if a production triage pipeline always calls with a consistent `num_ctx` (e.g. always 8192), this reload cost is paid once at pipeline startup (or after an idle gap exceeding `OLLAMA_KEEP_ALIVE`), not per alert. It is excluded from the per-alert extrapolation in §6.

## 5. Summary — median tokens/sec and total latency per condition

| Condition | n | Median decode tok/s | Median total_duration (s) | Median prompt tokens | Median output tokens |
|---|---|---|---|---|---|
| A — short prompt | 3 | **77.71** | 1.439 | 366 | 100 |
| B — realistic triage (free text) | 3 | **76.48** | 4.134 | 1364 | 300 |
| C — realistic triage (structured/JSON schema) | 3 | **73.87** | 4.235 | 1364 | 300 (139 on t3, see note above) |

## 6. Per-alert latency and extrapolation (THE headline numbers)

`OLLAMA_NUM_PARALLEL=1` is confirmed from the server log — this Ollama instance serves requests **strictly serially**. Multiple agent calls per alert cannot overlap in time on this host; a 4-agent-call pipeline pays the full cost of 4 sequential model invocations.

Two bases are given since B and C are both realistic single-alert-triage calls that differ only in output format (free text vs. schema-constrained JSON). A downstream design that will actually consume structured JSON (the more likely real design) should use the **C basis**; a design still doing free-text extraction should use the **B basis**. Both are close (~2.4% apart).

### Per-alert latency (median total_duration)

| Basis | 1 agent call (median) | 4 sequential agent calls |
|---|---|---|
| B (free-text triage) | 4.134 s | 16.535 s (0.276 min) |
| C (structured/JSON triage) | 4.235 s | 16.939 s (0.282 min) |

### Extrapolation — wall-clock cost at volume (serial execution, no concurrency)

**Basis: B (free-text triage), median total_duration = 4.134 s/call**

| Alerts | 1-agent pipeline | 4-agent pipeline |
|---|---|---|
| 1,000 | 1.15 h (0.048 d) | 4.59 h (0.191 d) |
| 10,000 | 11.48 h (0.478 d) | 45.93 h (1.914 d) |
| 90,000 | 103.34 h (4.306 d) | 413.38 h (17.224 d) |

**Basis: C (structured/JSON triage), median total_duration = 4.235 s/call**

| Alerts | 1-agent pipeline | 4-agent pipeline |
|---|---|---|
| 1,000 | 1.18 h (0.049 d) | 4.71 h (0.196 d) |
| 10,000 | 11.76 h (0.490 d) | 47.05 h (1.960 d) |
| 90,000 | 105.87 h (4.411 d) | 423.47 h (17.644 d) |

These figures exclude the one-time cold-start/reload cost (§4, ~2-3s) since it is amortized to near-zero at these volumes. They also assume this exact hardware/model/quantization/context configuration, batch size 1, `OLLAMA_NUM_PARALLEL=1` (no concurrency) — any of those changing (bigger/smaller model, higher parallelism, batching, different GPU) would move these numbers.

## 7. Files

- Benchmark driver: `/tmp/claude-1000/-home-kali-director/55824f36-a4ad-424d-acf2-90fc6b39f83a/scratchpad/bench.py`
- Raw results: `/tmp/claude-1000/-home-kali-director/55824f36-a4ad-424d-acf2-90fc6b39f83a/scratchpad/results.json`
- Prompts used: `prompt_a.txt`, `prompt_b.txt`, schema: `schema.json` (same directory)
- Cold-start warm-up capture: `warmup.json` (same directory)
