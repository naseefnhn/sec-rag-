<div align="center">

# 🛡️ SecRAG — Enterprise Security Intelligence Platform

**An air-gapped, zero-hallucination AI security analyst powered by Hybrid RAG.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Llama](https://img.shields.io/badge/LLM-Llama_3.1_(8B)-0468bf?logo=meta)](https://ollama.com/library/llama3.1)
[![ChromaDB](https://img.shields.io/badge/VectorDB-ChromaDB-purple)](https://www.trychroma.com/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*SecRAG fuses raw vulnerability data (NVD CVEs, MITRE CWEs) with actionable mitigation strategies (OWASP) entirely offline. Built with Reciprocal Rank Fusion and Cross-Encoder Reranking to mathematically guarantee factual accuracy.*

</div>

---

## ✨ The Problem It Solves

If a developer or penetration tester needs to deal with a vulnerability, they traditionally have to manually bounce between disconnected systems: NVD for the CVE score, MITRE for CWE theory, OWASP for mitigation steps, and WSTG for testing methodologies. It takes hours of reading and dozens of open tabs.

Worse, engineers **cannot** use ChatGPT or Claude to speed this up, because pasting highly-sensitive corporate code or zero-day vulnerability details into external cloud APIs is a massive data leak and compliance violation.

## 🚀 The Solution (SecRAG)

SecRAG is a **completely offline, privacy-first Intelligence Platform**. 
It aggregates the world’s fragmented security frameworks into a single, unified brain on your local machine.

- 🔒 **Absolute Privacy (Air-Gapped):** The entire architecture (Llama 3.1 LLM, ChromaDB, BM25) runs 100% locally. Query highly sensitive code without leaking data to cloud providers.
- 🎯 **Zero Hallucinations:** Uses a rigorous Hybrid Retrieval Architecture governed by strict "Amnesia Prompting" to completely block the LLM from inventing fake security advice.
- ⚡ **Instant Actionability:** Generates deep-dive analytical security reports for developers, or actionable penetration testing checklists for red-teamers.

---

## 🏗️ Elite RAG Architecture

SecRAG avoids the poor performance of "Naive RAG" by implementing a defense-in-depth retrieval pipeline:

```text
User Query
    │
    ├─► [1] Hybrid Search (Parallel Execution)
    │     ├── Dense Vector Search via ChromaDB (Semantic Meaning)
    │     └── Sparse Keyword Search via BM25 (Exact terms like "CVE-2025-1234")
    │
    ├─► [2] Reciprocal Rank Fusion (RRF)
    │     └── Mathematically merges both result sets into a diverse candidate pool.
    │
    ├─► [3] Neural Cross-Encoder Reranking
    │     └── A specialized AI reads the query & documents side-by-side to mercilessly drop irrelevant chunks (Score Cutoff: 0.15).
    │
    └─► [4] Llama 3.1 8B (128k Context)
          └── Generates the final grounded answer strictly confined to the retrieved data.
```

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| **LLM Inference** | `Ollama` hosting `Llama 3.1 (8B)` |
| **Embeddings** | `BAAI/bge-base-en-v1.5` (768-dim, English-optimized) |
| **Sparse Indexing** | `rank_bm25` (Offline Pickle Index) |
| **Reranker** | `cross-encoder/ms-marco-MiniLM-L-6-v2` |
| **Vector DB** | `ChromaDB` (Persistent) |
| **API Server** | `FastAPI` + `Uvicorn` |
| **Frontend** | `Streamlit` |

---

## 🚀 Installation & Setup

### 1. Prerequisites
- Python **3.10+**
- Ollama installed locally ([Download here](https://ollama.com/))
- At least **16GB RAM** (to comfortably run Llama 3.1 8B + Embedding models)

### 2. Pull the Local Model
```bash
ollama pull llama3.1
```

### 3. Clone and Setup Environment
```bash
git clone https://github.com/naseefnhn/sec-rag-.git
cd sec-rag-

# Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 4. Build the Offline Database
The knowledge base files (NVD, MITRE, OWASP PDFs) are large public datasets and must be downloaded manually to the `knowledge_base/` directory. (e.g. `nvdcve-2.0-2025.json`, `cwec_v4.18.xml`, `wstg-v4.2.pdf`).

Once downloaded, build your vector and BM25 indices:
```bash
python build_db.py
```
*Note: This will embed thousands of security documents locally. It may take 10-15 minutes on the first run.*

---

## ▶️ Running the Application

SecRAG requires two processes running simultaneously.

**Terminal 1 — Core Processing Server:**
```bash
python server.py
# Initializes HTTP tools, ChromaDB, BM25 Index, and Cross-Encoder
```

**Terminal 2 — Streamlit Interface:**
```bash
streamlit run app.py
# Open localhost:8501
```

---

## 🔒 Security & Privacy Guarantees

- **No API Keys:** Runs 100% locally via Ollama. No cloud provider accounts required.
- **Strict Amnesia Prompts:** The System Prompt aggressively forces the LLM to deny answers if the exact mitigation is not listed in the retrieved contexts, ensuring zero hallucinations.
- **Localhost Bound:** The FastAPI backend is bound solely to `127.0.0.1`, safely isolated from your exposed network.
- **Input Sanitization:** Guardrails drop known prompt injection vectors (`"Ignore previous instructions"`).

---

<div align="center">

Built with ❤️ for the security community.
*SecRAG — Defending systems through rigorous, verifiable intelligence.*

</div>
