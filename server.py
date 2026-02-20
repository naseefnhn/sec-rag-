from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import CrossEncoder
import yaml
import time
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
# TOOL 1: Search Knowledge Base
# ========================================

@app.post("/tools/search",response_model=ToolResponse)
def search(request: SearchRequest):
    """
    Search the security knowledge base for vulnerabilities, best practices, or remediation steps.
    Returns the most relevant text chunks with their metadata as JSON.
    
    Args:
        query: Search query string
        k: Number of results to return (default: 10)
    
    Returns:
        JSON string with structure: {"chunks": [{"content": str, "source": str, ...}], "query": str, "count": int}
    """
    try:
        if collection is None:
            return ToolResponse(
                status="error",
                data={},
                error="ChromaDB collection not initialized. Check server logs."
            )
        
        start_time = time.time()
        
        source_types = ["OWASP", "OWASP_WSTG", "NVD", "MITRE"]
        
        # Split the total requested results evenly across sources
        # Example: k=20 / 4 sources = 5 results per source
        # max(3, ...) ensures we always get at least 3 from each
        per_source_k = max(3, request.k // len(source_types))
        
        # Collect all chunks from all sources into one list
        chunks = []
        
        # Track content we've already added to avoid duplicates.
        # set() is like a checklist — we can quickly ask 
        # "have I seen this content before?" in O(1) time.
        already_added_content = set()
        
        # Search each source type independently
        for source in source_types:
            try:
                # Query ChromaDB filtered to ONE source type only
                # Example: where={"source": "OWASP"} → only OWASP docs
                results = collection.query(
                    query_texts=[request.query],
                    n_results=per_source_k,
                    where={"source": source}
                )
                
                # Process each result from this source
                for i in range(len(results["documents"][0])):
                    content = results["documents"][0][i]
                    
                    # DEDUPLICATION: Due to chunk overlap during ingestion,
                    # the same text can appear in multiple chunks.
                    # We check the first 200 characters as a fingerprint.
                    # If we've seen it before → skip. If new → add it.
                    fingerprint = content[:200]
                    if fingerprint in already_added_content:
                        continue  # Already have this content, skip it
                    already_added_content.add(fingerprint)
                    
                    # Extract all metadata stored during build_db.py ingestion
                    metadata = results["metadatas"][0][i]
                    chunks.append({
                        "content": content,
                        "title": metadata.get("title", ""),
                        "priority": metadata.get("priority", ""),
                        "score": round(1 - results["distances"][0][i], 3),
                        "source": metadata.get("source", "Unknown"),
                        "type": metadata.get("type", "unknown"),
                        "cve_id": metadata.get("cve_id", ""),
                        "cvss_score": metadata.get("cvss_score", 0.0),
                        "cwe_id": metadata.get("cwe_id", ""),
                        "published": metadata.get("published", "")
                    })
            except Exception:
                # If a source type has zero matching docs, skip it
                continue
        
        end_time = time.time()
        
        return ToolResponse(
            status="success",
            data={
                "chunks": chunks,
                "query": request.query,
                "count": len(chunks),
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
        
        # Sort all scored chunks from highest to lowest relevance
        scored_chunks.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        # Walk through sorted list: grab the FIRST (= best-scoring) 
        # chunk from each unique source. Put duplicates aside.
        already_selected_sources = set()
        one_per_source = []       # Best chunk from each source type
        duplicate_sources = []    # All other chunks (same source already picked)
        
        for chunk in scored_chunks:
            source = chunk.get("source", "Unknown")
            if source not in already_selected_sources:
                # First time seeing this source → keep it
                already_selected_sources.add(source)
                one_per_source.append(chunk)
            else:
                # Source already represented → save for later
                duplicate_sources.append(chunk)
        
        # Build final list: start with one-per-source picks,
        # then fill any remaining slots with next-best by score
        final_selection = one_per_source[:request.top_k]
        slots_remaining = request.top_k - len(final_selection)
        if slots_remaining > 0:
            final_selection.extend(duplicate_sources[:slots_remaining])
        
        # Sort final selection by score so highest relevance shows first
        top_chunks = sorted(final_selection, key=lambda x: x["relevance_score"], reverse=True)
        
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
