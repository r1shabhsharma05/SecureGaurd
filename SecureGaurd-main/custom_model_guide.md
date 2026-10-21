# Step-by-Step Guide: Integrating a Custom Trained AI Model into SecureGuard

This guide outlines how to train, host, and connect your own custom AI model (e.g. fine-tuned on code security vulnerabilities) to replace the default Gemini API/Local rule engine fallback.

---

## Step 1: Choose a Base Model

For code analysis and vulnerability remediation, you should start with a specialized coder/software model.

- **DeepSeek-Coder-1.3B / 6.7B** (Highly recommended: fast, lightweight, and extremely good at coding tasks).
- **Qwen2.5-Coder-1.5B / 7B** (State-of-the-art reasoning for its size).
- **CodeLlama-7B** (Standard open-source baseline).

*Tip: A 1.3B or 1.5B model is lightweight enough to run on a local developer GPU (or even CPU/MacBook) while maintaining high speed.*

---

## Step 2: Prepare Your Dataset

You need to fine-tune the model to convert vulnerable code blocks into secure code. Format your dataset in a JSON file containing instruction-response pairs:

```json
[
  {
    "instruction": "Fix the following Potential SQL Injection vulnerability in this Node.js snippet.",
    "input": "const query = `SELECT * FROM users WHERE id = ${req.query.id}`;",
    "output": "const query = 'SELECT * FROM users WHERE id = ?';\nconst [rows] = await db.execute(query, [req.query.id]);"
  }
]
```

*Recommended Datasets:*

- **OWASP Benchmark datasets**.
- **GitHub Security Advisory (GHSA)** public commit diffs.
- Synthetic generation (use Gemini/GPT-4 to write 1,000 vulnerable snippets and their corresponding secure fixes).

---

## Step 3: Train/Fine-Tune the Model (QLoRA)

Use **QLoRA** (Quantized Low-Rank Adaptation) to train the model on a single GPU using Hugging Face libraries (`peft`, `transformers`, `trl`) or the **Unsloth** library (which is 2-5x faster).

Here is a simple training script overview using Python:

```python
from datasets import load_dataset
from trl import SFTTrainer
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from peft import LoraConfig

model_id = "deepseek-ai/deepseek-coder-1.3b-base"
model = AutoModelForCausalLM.from_pretrained(model_id, load_in_4bit=True, device_map="auto")
tokenizer = AutoTokenizer.from_pretrained(model_id)

dataset = load_dataset("json", data_files="my_security_dataset.json")

peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

training_args = TrainingArguments(
    output_dir="./secureguard-model",
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,
    learning_rate=2e-4,
    logging_steps=10,
    max_steps=500,
    fp16=True
)

trainer = SFTTrainer(
    model=model,
    train_dataset=dataset["train"],
    peft_config=peft_config,
    max_seq_length=1024,
    dataset_text_field="text",
    args=training_args
)

trainer.train()
trainer.model.save_pretrained("./secureguard-model-final")
```

---

## Step 4: Host Your Custom Model (Inference Server)

Once trained, convert and host your model so it exposes a standard API.

### Option A: Using Ollama (Easiest for local development)

1. Convert your trained PyTorch weights to GGUF format (using `llama.cpp`).
2. Create a `Modelfile` containing:
   ```dockerfile
   FROM ./my-custom-model.gguf
   SYSTEM "You are a senior security engineer. Always return valid JSON matching the requested structure."
   ```
3. Create the model in Ollama:
   ```bash
   ollama create secureguard-ai -f ./Modelfile
   ```
4. Ollama automatically hosts the model at: `http://localhost:11434/v1/chat/completions` (OpenAI-compatible format).

### Option B: Using vLLM or Hugging Face TGI (For Production / Cloud)

Run vLLM in a Docker container on an AWS/GCP GPU instance:

```bash
python -m vllm.entrypoints.openai.api_server \
    --model /path/to/fine-tuned-model \
    --port 8000
```

This serves the API at `http://YOUR_SERVER_IP:8000/v1/chat/completions`.

---

## Step 5: Connect to SecureGuard Backend

To route requests to your new custom model, edit the AI engine in `backend/utils/aiFixEngine.js`.

Replace the `callGeminiAPI` function with a fetch call targeting your hosted server. Here is how your code will look:

```javascript
// Add/Edit this function in backend/utils/aiFixEngine.js
async function callCustomTrainedModel(vulnerability) {
  const { title, codeSnippet, filePath, severity } = vulnerability;

  const prompt = `Analyze this vulnerability and provide a production-ready secure code fix.
Vulnerability: ${title}
File: ${filePath}
Code:
${codeSnippet}

Return JSON with exactly these keys: "fixedCode", "explanation", "confidence", "cweId".`;

  const response = await fetch("http://localhost:11434/v1/chat/completions", { // Pointing to local Ollama / vLLM
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "secureguard-ai", // Your custom model name
      messages: [
        { role: "user", content: prompt }
      ],
      temperature: 0.1
    })
  });

  if (!response.ok) throw new Error(`Custom model API error: ${response.status}`);

  const data = await response.json();
  const text = data.choices[0].message.content;

  // Extract and parse JSON
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error("Could not parse model response");
  
  const parsed = JSON.parse(jsonMatch[0]);
  return {
    fixedCode: parsed.fixedCode || "",
    explanation: parsed.explanation || "",
    confidence: parsed.confidence || 90,
    cweId: parsed.cweId || "CWE-20",
    cvssScore: 7.5,
    references: [],
    engine: "custom-fine-tuned"
  };
}
```

Then update `generateAiFix` to call your custom model:

```javascript
async function generateAiFix(vulnerability) {
  try {
    // Calls your custom inference server
    return await callCustomTrainedModel(vulnerability);
  } catch (err) {
    console.warn("[AI Engine] Custom model failed, using local rule fallback:", err.message);
    // Local rule engine fallback
    const rule = FIX_RULES[vulnerability.title] || DEFAULT_FIX;
    return {
      fixedCode: rule.fixTemplate(vulnerability.codeSnippet || ""),
      explanation: rule.explanation,
      confidence: rule.confidence,
      cweId: rule.cweId,
      cvssScore: rule.cvssScore || 5.0,
      references: rule.references || [],
      engine: "rule-based"
    };
  }
}
```

---

## Step 6: Train Your Own Severity-Ranker Weights (Prioritization Model)

The severity-priority ranker (`backend/services/severity-ranker/`) ships with
v0 weights trained on heuristic-derived labels (see `docs/severity-ranker.md`
for the caveat). You can replace them with weights trained on your own
analyst-labeled data — the 0–100 serving contract stays identical, so no
endpoint, Node route, or Dashboard code changes.

**1. Prepare a labeled CSV** with the same 18 raw features as
`sample_findings.csv`, plus a `priority` column (0–100, your analysts'
"fix-first" judgment per finding).

**2. Train:**

```bash
cd backend/services/severity-ranker
python train_severity.py --data /path/to/your_labeled.csv
```

The script reuses the FP classifier's fitted encoders and shared
`FEATURE_COLS`, evaluates on a held-out split (watch Spearman ρ — rank order
is what matters), and writes `severity_model.joblib` + `severity_metadata.json`.

**3. Version honestly:** edit `severity_metadata.json` — set `version` to
`v1_analyst` (or your scheme) and `label_source` to describe your labeling
process. The `/health` endpoint reports this version, so you can confirm the
deploy picked up your weights.

**4. Validate before relying on it:** check held-out Spearman ρ ≥ 0.9 and
spot-check the top-20 ranked findings against analyst judgment. A ranker that
disagrees with your analysts on the top of the queue is worse than the
heuristic v0 — keep v0 until v1 earns the swap.
