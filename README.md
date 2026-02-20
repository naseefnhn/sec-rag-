<div align="center">

# 🛡️ SecRAG — Security Intelligence Platform

**AI-powered security analyst powered by Retrieval-Augmented Generation (RAG)**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Gemini](https://img.shields.io/badge/LLM-Gemini%202.5%20Flash-orange?logo=google)](https://aistudio.google.com)
[![ChromaDB](https://img.shields.io/badge/VectorDB-ChromaDB-purple)](https://www.trychroma.com/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*SecRAG answers security questions grounded exclusively in structured knowledge from OWASP, NVD CVEs, MITRE CWEs, and the OWASP Web Security Testing Guide — no hallucinations, source-traced answers only.*

</div>

---

## ✨ What is SecRAG?

SecRAG is a **security-focused RAG system** that:

- 🔍 **Searches** a curated vector database of security knowledge (OWASP, CVE, CWE, WSTG)
- 🎯 **Reranks** results using a cross-encoder for maximum relevance
- 📄 **Generates** structured security reports from findings
- 🤖 **Answers** your questions using only retrieved, verifiable context
- 🚫 **Blocks** prompt injection and enforces source-grounded responses

It operates through a **decoupled architecture**: a persistent FastAPI tool server (`server.py`) and a Streamlit frontend (`app.py`), connected over HTTP.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                 Streamlit UI (app.py)            │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Search  │→ │  Rerank  │→ │ Gen. Report  │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│         ↑ HTTP calls to localhost:8000           │
└─────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│            FastAPI Tool Server (server.py)       │
│  POST /tools/search  →  ChromaDB vector search  │
│  POST /tools/rerank  →  Cross-encoder reranking  │
│  POST /tools/generate_report  →  Report builder  │
└─────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│         ChromaDB (chroma_db/ — local)           │
│  OWASP Cheat Sheets  │  NVD CVEs  │  MITRE CWEs │
│  OWASP WSTG PDF      │            │             │
└─────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│              Google Gemini 2.5 Flash             │
│    Grounded answering from security report       │
└─────────────────────────────────────────────────┘
```

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| **LLM** | Google Gemini 2.5 Flash |
| **Embeddings** | `BAAI/bge-base-en-v1.5` (768-dim, via SentenceTransformers) |
| **Reranker** | `cross-encoder/ms-marco-MiniLM-L-6-v2` |
| **Vector DB** | ChromaDB (persistent, local) |
| **API Server** | FastAPI + Uvicorn |
| **Frontend** | Streamlit |
| **Knowledge Sources** | OWASP Cheat Sheets, NVD CVE JSON, MITRE CWE XML, OWASP WSTG PDF |

---

## 📋 Prerequisites

- Python **3.10+**
- A **Google Gemini API key** → [Get one here](https://aistudio.google.com/app/apikey)
- At least **4GB RAM** (for embedding model + cross-encoder)

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/naseefnhn/sec-rag-.git
cd sec-rag-
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
# Copy the template
cp .env.example .env

# Edit .env and add your Gemini API key
# GOOGLE_API_KEY=your_actual_key_here
```

---

## 📚 Knowledge Base Setup

The knowledge base files are **not included** in this repository (large public datasets). Download them manually:

### Required Files (place in `knowledge_base/` directory)

| File | Source | How to get |
|---|---|---|
| `nvdcve-2.0-2025.json` | NVD (NIST) | [nvd.nist.gov/vuln/data-feeds](https://nvd.nist.gov/vuln/data-feeds) — Download CVE JSON 2025 feed |
| `nvdcve-2.0-modified.json` | NVD (NIST) | Same page — Download "modified" feed |
| `cwec_v4.18.xml` | MITRE CWE | [cwe.mitre.org/data/downloads.html](https://cwe.mitre.org/data/downloads.html) — Download CWE XML |
| `wstg-v4.2.pdf` | OWASP | [owasp.org/www-project-web-security-testing-guide](https://owasp.org/www-project-web-security-testing-guide/) |

> **OWASP Cheat Sheets** are fetched live from the web by `build_db.py` — no download needed.

### Build the vector database

```bash
python build_db.py
```

This will:
- Fetch and clean 12 OWASP Cheat Sheets
- Load and filter CVEs (web-security focused, CVSS ≥ 4.0, last 18 months)
- Load 46 priority CWEs (SANS Top 25 + Web + API CWEs)
- Load the OWASP WSTG PDF
- Embed everything into ChromaDB using `bge-base-en-v1.5`

Expected output: `✓ Total documents added to collection: ~XXXX`

---

## ▶️ Running the Application

SecRAG requires **two processes** running simultaneously in separate terminals:

### Terminal 1 — Start the tool server

```bash
python server.py
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     ChromaDB Initialized: XXXX documents
INFO:     Cross-encoder reranker initialized
```

### Terminal 2 — Start the Streamlit UI

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## 🖥️ Usage

### Output Modes (switchable from sidebar)

| Mode | Description |
|---|---|
| 📊 **Analysis Mode** | Structured 5-section response: Overview → Technical Details → Testing Steps → Mitigation → Tools |
| ✅ **Checklist Mode** | Actionable `[ ]` pentest checklist — no theory, only steps |

### Example Queries

```
How to prevent SQL injection in a Python Flask app?
What are the latest XSS CVEs?
Explain SSRF and how to test for it
What does CWE-79 mean?
How should session tokens be managed securely?
```

### RAG Pipeline (per query)

```
User Query
    → [1] Semantic search across OWASP/CVE/CWE/WSTG (ChromaDB)
    → [2] Cross-encoder reranking (top 5 of 20)
    → [3] Security report generation (structured findings)
    → [4] Gemini LLM answer (grounded in report)
    → Response displayed with expandable source/context panels
```

---

## ⚙️ Configuration

All non-secret configuration lives in `config.yaml`:

```yaml
app:
  name: "SecRAG Intelligence Platform"
  version: "1.0.0"
  model: "gemini-2.5-flash"       # Change Gemini model here

database:
  path: "./chroma_db"              # Local vector DB path
  collection_name: "security_knowledge"
  embedding_model: "BAAI/bge-base-en-v1.5"

mcp:
  server_name: "secrag-tools"
  transport: "stdio"
```

---

## 🔒 Security Design

SecRAG is built with a **defense-in-depth** approach:

| Measure | Implementation |
|---|---|
| **No hardcoded secrets** | All API keys loaded from `.env` via `python-dotenv` |
| **Prompt injection protection** | Keyword-based blocklist in `app.py::is_safe_query()` |
| **Source-only answering** | LLM instructed to answer *only* from retrieved context |
| **Local-first architecture** | ChromaDB runs fully locally — no data sent to external DB |
| **Localhost-only server** | FastAPI bound to `127.0.0.1:8000` — not exposed to network |
| **Input sanitization** | Queries validated before vector search |

---

## 📁 Project Structure

```
sec-rag/
├── app.py              # Streamlit frontend + LLM integration
├── server.py           # FastAPI tool server (search, rerank, report)
├── build_db.py         # Knowledge base ingestion pipeline
├── config.yaml         # Non-secret application configuration
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template (safe to commit)
├── .env                # Your actual API key (NEVER commit this)
├── .gitignore          # Protects secrets and large files
├── knowledge_base/     # Data files (not in repo — download separately)
│   ├── nvdcve-2.0-2025.json
│   ├── nvdcve-2.0-modified.json
│   ├── cwec_v4.18.xml
│   └── wstg-v4.2.pdf
└── chroma_db/          # Generated vector DB (not in repo)
```

---

## 🧪 Running Tests

```bash
python test_db.py       # Verify ChromaDB connectivity and document count
python test_chunking.py # Validate chunking strategy
python test_fixes.py    # Smoke test for known edge cases
```

---

## 🛠️ Troubleshooting

| Issue | Solution |
|---|---|
| `❌ Server: Offline` in UI | Run `python server.py` in a separate terminal |
| `ChromaDB collection not initialized` | Run `python build_db.py` first |
| `Empty response from Gemini LLM` | Check your `GOOGLE_API_KEY` in `.env` |
| Slow first response | Embedding model downloads on first run (~400MB) |
| `knowledge_base/*.json not found` | Download NVD feeds (see Knowledge Base Setup) |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'feat: add your feature'`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

> **Security contributions**: If you find a security issue in this project itself, please open a private issue rather than a public one.

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 📚 Knowledge Sources

This project uses publicly available security data:

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — Creative Commons
- [NVD CVE Database](https://nvd.nist.gov/) — Public domain (U.S. Government)
- [MITRE CWE](https://cwe.mitre.org/) — Public use permitted
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Creative Commons

---

<div align="center">

Built with ❤️ for the security community

*SecRAG — Know your vulnerabilities before attackers do.*

</div>
