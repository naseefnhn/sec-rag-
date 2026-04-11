from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import CrossEncoder
import yaml
import time
import pickle
from datetime import datetime
import logging
import uvicorn

# -------------------------------------------------
# Logging
# -------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secrag")


# Load Configuration

def load_config():  
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

app = FastAPI()

try:
    logging.info("Initializing ChromaDB...")
    db_client = chromadb.PersistentClient(path=config['database']['path'])
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=config['database']['embedding_model']
    )
    collection = db_client.get_or_create_collection(
        name=config['database']['collection_name'],
        embedding_function=emb_fn
    )
    logging.info(f"ChromaDB Initialized: {collection.count()} documents")
except Exception as e:
    logging.error(f"Failed to initialize ChromaDB: {e}")
    collection = None

try:
    cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
    logging.info("Cross-encoder reranker initialized")
except Exception as e:
    logging.error(f"Failed to initialize reranker: {e}")
    cross_encoder = None

# -------------------------------------------------
# BM25 Sparse Index (for keyword search)
# -------------------------------------------------
bm25_index = None
bm25_corpus_texts = []
bm25_corpus_metadata = []
bm25_corpus_ids = []

try:
    bm25_path = config.get("search", {}).get("bm25_index_path", "./bm25_index.pkl")
    with open(bm25_path, "rb") as f:
        bm25_data = pickle.load(f)
    bm25_index = bm25_data["bm25"]
    bm25_corpus_texts = bm25_data["corpus_texts"]
    bm25_corpus_metadata = bm25_data["corpus_metadata"]
    bm25_corpus_ids = bm25_data["corpus_ids"]
    logging.info(f"BM25 index loaded: {len(bm25_corpus_texts)} documents")
except FileNotFoundError:
    logging.warning("BM25 index not found. Run build_db.py to create it. Falling back to dense-only search.")
except Exception as e:
    logging.error(f"Failed to load BM25 index: {e}")

class SearchRequest(BaseModel):
    query: str
    k: int = 10

class RerankRequest(BaseModel):
    query: str
    chunks: List[Dict[str, Any]]
    top_k: int = 5

class ReportRequest(BaseModel):
    findings: List[Dict[str, Any]]
    format: str = "markdown"

class ToolResponse(BaseModel):
    status: str
    data: Dict[str, Any] = {}
    error: Optional[str] = None

@app.get("/")
def root():
    """Health check"""
    return {
        "status": "running",
        "version": "1.0.0",
        "documents": collection.count() if collection else 0,
        "tools": ["tools/search", "tools/rerank", "tools/generate_report"]
    }

# ========================================
# RRF: Reciprocal Rank Fusion
# ========================================

def reciprocal_rank_fusion(dense_results: list, bm25_results: list, k: int = 60) -> list:
    """
    Merge two ranked lists using Reciprocal Rank Fusion.
    
    For each document d appearing in any list:
      rrf_score(d) = Σ 1/(k + rank_i)
    
    Documents found by BOTH engines get score-boosted.
    k=60 is the constant from the original RRF paper.
    """
    scores = {}
    
    for rank, doc in enumerate(dense_results):
        doc_id = doc.get("doc_id", doc["content"][:100])
        scores[doc_id] = {"doc": doc, "score": 1.0 / (k + rank + 1)}
    
    for rank, doc in enumerate(bm25_results):
        doc_id = doc.get("doc_id", doc["content"][:100])
        if doc_id in scores:
            # Found by BOTH engines → boost score
            scores[doc_id]["score"] += 1.0 / (k + rank + 1)
        else:
            # Found ONLY by BM25
            scores[doc_id] = {"doc": doc, "score": 1.0 / (k + rank + 1)}
    
    fused = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
    return [item["doc"] for item in fused]


def _extract_chunk(content, doc_id, metadata, score):
    """Helper: build a chunk dict from raw data."""
    return {
        "content": content,
        "doc_id": doc_id,
        "title": metadata.get("title", ""),
        "priority": metadata.get("priority", ""),
        "score": round(score, 3),
        "source": metadata.get("source", "Unknown"),
        "type": metadata.get("type", "unknown"),
        "cve_id": metadata.get("cve_id", ""),
        "cvss_score": metadata.get("cvss_score", 0.0),
        "cwe_id": metadata.get("cwe_id", ""),
        "published": metadata.get("published", "")
    }


# ========================================
# TOOL 1: Hybrid Search Knowledge Base
# ========================================

@app.post("/tools/search",response_model=ToolResponse)
def search(request: SearchRequest):
    """
    Hybrid search: Dense (ChromaDB) + BM25 (keyword) → RRF fusion.
    Replaces the old source-stratified dense-only search.
    
    Args:
        query: Search query string
        k: Number of results to return (default: 10)
    
    Returns:
        JSON with fused chunks from both search engines.
    """
    try:
        if collection is None:
            return ToolResponse(
                status="error",
                data={},
                error="ChromaDB collection not initialized. Check server logs."
            )
        
        start_time = time.time()
        retrieval_k = config.get("search", {}).get("initial_retrieval_k", 20)
        rrf_k = config.get("search", {}).get("rrf_k", 60)
        
        # ═══════════════════════════════════════
        # PATH A: Dense search (ChromaDB) — semantic
        # ═══════════════════════════════════════
        # ONE global query — no source filtering.
        # Let the best chunks from ANY source surface.
        dense_raw = collection.query(
            query_texts=[request.query],
            n_results=retrieval_k
        )
        
        dense_results = []
        for i in range(len(dense_raw["documents"][0])):
            meta = dense_raw["metadatas"][0][i]
            dense_results.append(_extract_chunk(
                content=dense_raw["documents"][0][i],
                doc_id=dense_raw["ids"][0][i],
                metadata=meta,
                score=1 - dense_raw["distances"][0][i]
            ))
        
        # ═══════════════════════════════════════
        # PATH B: BM25 search (sparse) — keyword
        # ═══════════════════════════════════════
        # Finds exact matches for CVE IDs, CWE numbers, acronyms.
        bm25_results = []
        if bm25_index is not None:
            tokenized_query = request.query.lower().split()
            bm25_scores = bm25_index.get_scores(tokenized_query)
            
            # Get top-k indices sorted by BM25 score (highest first)
            top_indices = sorted(
                range(len(bm25_scores)),
                key=lambda i: bm25_scores[i],
                reverse=True
            )[:retrieval_k]
            
            for idx in top_indices:
                if bm25_scores[idx] > 0:  # Only include if BM25 found a match
                    bm25_results.append(_extract_chunk(
                        content=bm25_corpus_texts[idx],
                        doc_id=bm25_corpus_ids[idx],
                        metadata=bm25_corpus_metadata[idx],
                        score=float(bm25_scores[idx])
                    ))
        else:
            logger.warning("BM25 index not loaded — using dense-only search")
        
        # ═══════════════════════════════════════
        # FUSION: Reciprocal Rank Fusion
        # ═══════════════════════════════════════
        fused_chunks = reciprocal_rank_fusion(dense_results, bm25_results, k=rrf_k)
        
        # Deduplicate by content fingerprint
        seen = set()
        unique_chunks = []
        for chunk in fused_chunks:
            fp = chunk["content"][:200]
            if fp not in seen:
                seen.add(fp)
                unique_chunks.append(chunk)
        
        # Return top-k
        final_chunks = unique_chunks[:request.k]
        
        end_time = time.time()
        
        logger.info(f"Hybrid search: {len(dense_results)} dense + {len(bm25_results)} BM25 → {len(final_chunks)} fused (query: {request.query[:50]})")
        
        return ToolResponse(
            status="success",
            data={
                "chunks": final_chunks,
                "query": request.query,
                "count": len(final_chunks),
                "dense_count": len(dense_results),
                "bm25_count": len(bm25_results),
                "query_time": round(end_time - start_time, 3)
            }
        )

    except Exception as e:
        return ToolResponse(
            status="error",
            data={},
            error=str(e)
        )

# ========================================
# TOOL 2: Rerank Context
# ========================================

@app.post("/tools/rerank",response_model=ToolResponse)
def rerank_context(request: RerankRequest):
    """
    Rerank retrieved chunks using cross-encoder for better relevance.
    
    Args:
        query: Original search query
        chunks: List of chunks from search tool (each chunk is a dict with 'content', 'source', etc.)
        top_k: Number of top results to return after reranking (default: 5)
    
    Returns:
        JSON string with reranked chunks and relevance scores
    """
    try:
        if not cross_encoder:
            return ToolResponse(
                status="error",
                data={},
                error="Reranker not initialized"
            )
        
        if not request.chunks or not isinstance(request.chunks, list):
            return ToolResponse(
                status="error",
                data={},
                error="Invalid chunks format"
            )
        
        start_time = time.time()
        
        # Extract content for reranking
        texts = [chunk.get("content", "") for chunk in request.chunks]
        
        # Create query-document pairs
        pairs = [[request.query, text] for text in texts]
        
        # Get relevance scores from cross-encoder
        scores = cross_encoder.predict(pairs)
        
        # Combine chunks with scores and sort by relevance
        scored_chunks = []
        for i, chunk in enumerate(request.chunks):
            scored_chunk = chunk.copy()
            scored_chunk["relevance_score"] = round(float(scores[i]), 4)
            scored_chunks.append(scored_chunk)
        
        # SCORE CUTOFF: Drop garbage chunks that the cross-encoder
        # determined are largely irrelevant.
        # 0.15 keeps "good-enough" chunks while filtering true garbage (negative scores).
        # Old value was 1.0 — way too aggressive, dropped ~70% of relevant chunks.
        RELEVANCE_CUTOFF = config.get("search", {}).get("rerank_cutoff", 0.15)
        all_scored = scored_chunks.copy()  # Keep a copy for fallback
        before_cutoff = len(scored_chunks)
        scored_chunks = [c for c in scored_chunks if c["relevance_score"] >= RELEVANCE_CUTOFF]
        dropped = before_cutoff - len(scored_chunks)
        if dropped > 0:
            logger.info(f"Score cutoff: dropped {dropped}/{before_cutoff} chunks below {RELEVANCE_CUTOFF}")
        
        # FALLBACK: Guarantee minimum chunks reach the LLM.
        # If cutoff was too aggressive for this query, take top-N by score regardless.
        min_chunks = config.get("search", {}).get("min_chunks_fallback", 3)
        if len(scored_chunks) < min_chunks:
            scored_chunks = sorted(all_scored, key=lambda x: x["relevance_score"], reverse=True)[:min_chunks]
            logger.warning(f"Fallback: only {len(scored_chunks)} chunks above cutoff, taking top {min_chunks}")
        
        # Sort all scored chunks from highest to lowest relevance
        scored_chunks.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        top_chunks = scored_chunks[:request.top_k]
        
        end_time = time.time()
        
        return ToolResponse(
            status="success",
            data={
                "chunks": top_chunks,
                "query": request.query,
                "original_count": len(request.chunks),
                "reranked_count": len(top_chunks),
                "rerank_time": round(end_time - start_time, 3)
            }
        )
        
    except Exception as e:
        return ToolResponse(
            status="error",
            data={},
            error=str(e)
        )



# ========================================
# TOOL 3: Generate Security Report
# ========================================

@app.post("/tools/generate_report", response_model=ToolResponse)
def generate_report(request: ReportRequest):
    """Generate a formatted security report based on findings."""
    try:
        if request.format != "markdown":
            return ToolResponse(status="error", data={}, error="Only markdown format supported")
        
        if not request.findings:
            return ToolResponse(status="error", data={}, error="No findings provided")
        
        # Sort: CVEs with CVSS bubble up by severity, others by relevance
        sorted_findings = sorted(
            request.findings,
            key=lambda x: (
                -(x.get("cvss_score", 0) or 0),
                -(x.get("relevance_score", 0) or 0)
            )
        )
        
        # Count CVEs with CVSS scores for summary
        critical_count = sum(1 for f in sorted_findings if (f.get("cvss_score", 0) or 0) >= 9.0)
        high_count = sum(1 for f in sorted_findings if 7.0 <= (f.get("cvss_score", 0) or 0) < 9.0)
        
        report = f"""# 🛡️ SecRAG Security Analysis Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Findings**: {len(sorted_findings)}  
{"🔴 **Critical**: " + str(critical_count) + "  " if critical_count else ""}{"🟠 **High**: " + str(high_count) if high_count else ""}

---

## 📊 Executive Summary

This report contains {len(sorted_findings)} security-related findings sorted by severity (CVSS) and relevance.
{"⚠️ **" + str(critical_count) + " CRITICAL severity finding(s) detected** — immediate review recommended." if critical_count else "✅ No critical-severity vulnerabilities found in the retrieved content."}

---

## 🔍 Detailed Findings

"""
        for idx, finding in enumerate(sorted_findings, 1):
            source = finding.get("source", "Unknown")
            content = finding.get("content", "")
            cve_id = finding.get("cve_id", "")
            cwe_id = finding.get("cwe_id", "")
            cvss = finding.get("cvss_score", 0) or 0
            relevance_score = finding.get("relevance_score", 0)
            priority = finding.get("priority", "")
            title = finding.get("title", "")
            
            report += f"### Finding #{idx}: {source}\n\n"
            
            # CVSS-based severity (only for findings with CVSS)
            if cvss >= 9.0:
                report += f"🔴 **Severity**: CRITICAL (CVSS {cvss}/10.0)  \n"
            elif cvss >= 7.0:
                report += f"🟠 **Severity**: HIGH (CVSS {cvss}/10.0)  \n"
            elif cvss >= 4.0:
                report += f"🟡 **Severity**: MEDIUM (CVSS {cvss}/10.0)  \n"
            elif cvss > 0:
                report += f"🟢 **Severity**: LOW (CVSS {cvss}/10.0)  \n"
            
            if title:
                report += f"**Title**: {title}  \n"
            if cve_id:
                report += f"**CVE ID**: {cve_id}  \n"
            if cwe_id:
                report += f"**CWE ID**: {cwe_id}  \n"
            if priority:
                report += f"**Priority**: {priority}  \n"
            if relevance_score:
                report += f"**Relevance Score**: {relevance_score:.3f}  \n"
            report += "\n"
            
            # Full content (no truncation — this is the complete reference)
            report += f"**Content**:\n```\n{content}\n```\n\n"
            report += "---\n\n"
        
        # Recommendations
        report += "## 📋 Recommendations\n\n"
        
        if critical_count > 0:
            report += "### 🔴 Immediate Actions Required\n"
            report += "- Review all CRITICAL findings immediately\n"
            report += "- Patch affected systems and dependencies\n"
            report += "- Verify exposure using the referenced CVE details\n\n"
        
        if high_count > 0:
            report += "### 🟠 High Priority Review\n"
            report += "- Assess HIGH severity findings for applicability\n"
            report += "- Plan remediation within current sprint\n\n"
        
        report += "### ✅ General Best Practices\n"
        report += "- Always validate and sanitize user input\n"
        report += "- Keep all software and dependencies up to date\n"
        report += "- Follow OWASP security guidelines\n"
        report += "- Implement defense-in-depth strategies\n"
        report += "- Conduct regular security audits and penetration testing\n\n"
        report += "---\n\n"
        report += "*Report generated by SecRAG - Security Intelligence Platform*\n"
        
        return ToolResponse(
            status="success",
            data={"report": report}
        )
    
    except Exception as e:
        return ToolResponse(
            status="error",
            data={},
            error=str(e)
        )

# ========================================
# RUN SERVER
# ========================================

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )
