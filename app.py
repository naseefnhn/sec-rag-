import streamlit as st
import os
import yaml
import requests
import ollama
import re
from dotenv import load_dotenv

load_dotenv()

# Page Config
st.set_page_config(page_title="SecRAG Intelligence", page_icon="🛡️", layout="wide")

# Load Config
def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()


# ========================================
# OLLAMA LLM HELPER
# ========================================

def call_ollama(system_prompt: str, user_prompt: str, temperature: float = 0.4, max_tokens: int = 4000) -> str:
    """
    Unified Ollama LLM call with system prompt support.
    """
    try:
        response = ollama.chat(
            model=config["app"]["model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            options={
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": config.get("ollama", {}).get("num_ctx", 8192)
            }
        )
        
        text = response["message"]["content"]
        if not text or not text.strip():
            raise ValueError("Empty response from Ollama")
        
        return text.strip()
    
    except Exception as e:
        raise RuntimeError(f"Ollama LLM call failed: {e}")
SERVER_URL = "http://127.0.0.1:8000"


# ========================================
# SERVER & TOOLS
# ========================================

def check_server():
    """Check if HTTP server is running"""
    try:
        response = requests.get(f"{SERVER_URL}/", timeout=2)
        return response.status_code == 200
    except:
        return False

def call_tool(endpoint: str, data: dict):
    """Call HTTP endpoint"""
    try:
        response = requests.post(
            f"{SERVER_URL}/tools/{endpoint}",
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result["status"] == "success":
                return result["data"]
            else:
                return {"error": result.get("error", "Unknown error")}
        else:
            return {"error": f"HTTP {response.status_code}: {response.text}"}
    
    except requests.exceptions.Timeout:
        return {"error": "Request timeout"}
    except Exception as e:
        return {"error": str(e)}


# ========================================
# SMART QUERY ROUTING (Inverted Logic)
# ========================================

def is_security_query(text: str) -> bool:
    """
    Detect if the input is a security-related query.
    Returns True  → route to full RAG pipeline
    Returns False → route to direct LLM (greeting/casual)
    
    Inverted logic: instead of trying to detect all greetings (impossible),
    we detect security queries (finite, well-defined vocabulary).
    """
    text_lower = text.lower().strip()
    words = text_lower.replace('-', ' ').split()
    
    # Any input longer than 4 words is likely a real question → RAG
    if len(words) > 4:
        return True
    
    # Security-related keywords (finite, well-defined)
    security_keywords = [
        # Vulnerability types
        'vulnerability', 'exploit', 'injection', 'xss', 'csrf', 'ssrf',
        'sql', 'sqli', 'rce', 'lfi', 'rfi', 'xxe', 'idor',
        'overflow', 'buffer', 'heap', 'stack',
        'deserialization', 'traversal', 'clickjacking',
        
        # Security concepts
        'authentication', 'authorization', 'encryption', 'hashing',
        'certificate', 'tls', 'ssl', 'oauth', 'jwt', 'token',
        'session', 'cookie', 'cors', 'csp', 'firewall',
        'sandbox', 'privilege', 'escalation',
        
        # Attack/defense terms  
        'attack', 'payload', 'malware', 'ransomware', 'phishing',
        'brute', 'denial', 'ddos', 'dos', 'mitm',
        'pentest', 'penetration', 'scan', 'nmap', 'burp',
        
        # Security domains
        'owasp', 'cve', 'cwe', 'cvss', 'mitre',
        'security', 'secure', 'vulnerability', 'hardening',
        'patch', 'remediation', 'mitigation',
        
        # Web/API terms in security context
        'api', 'endpoint', 'header', 'request', 'response',
        'sanitize', 'validate', 'whitelist', 'blacklist',
        'input', 'output', 'encoding', 'escaping',
        
        # Tools
        'wireshark', 'metasploit', 'sqlmap', 'nikto', 'zap',
        'hydra', 'john', 'hashcat', 'gobuster', 'dirb',
        
        # General security action words
        'protect', 'prevent', 'defend', 'harden', 'audit',
        'breach', 'leak', 'expose', 'compromise'
    ]
    
    # Check if ANY word in the input matches a security keyword
    return any(word in security_keywords for word in words)


def is_safe_query(query: str) -> bool:
    """Block prompt injection attempts"""
    dangerous = [
        "ignore previous instructions",
        "ignore all instructions",
        "you are now",
        "forget your instructions",
        "disregard above",
        "system prompt"
    ]
    query_lower = query.lower()
    return not any(d in query_lower for d in dangerous)


def get_casual_response(prompt: str) -> str:
    """
    Direct LLM call for non-security queries (greetings, casual chat, off-topic).
    No RAG pipeline — fast and natural.
    """
    try:
        system_prompt = """You are SecRAG, an AI-powered cybersecurity intelligence assistant.

ABOUT YOU (use this to introduce yourself when asked):
- You are a Hybrid RAG (Retrieval-Augmented Generation) security tool that searches a curated knowledge base of real vulnerability data.
- Your knowledge base contains: NVD CVEs (real-world vulnerabilities with severity scores), MITRE CWEs (root cause definitions), OWASP Cheat Sheets (developer defense guides), and the OWASP Web Security Testing Guide (penetration testing methodologies).
- You run 100% offline for data privacy — no queries leave the local machine.
- You can help with: vulnerability analysis, CVE lookups, security best practices, penetration testing checklists, and understanding attack techniques.

Rules:
- For greetings: Welcome the user warmly (2 sentences max). Briefly say you are SecRAG, a cybersecurity intelligence assistant. Do NOT suggest example queries or questions.
- For "what are you" / "who are you": Explain your purpose using the ABOUT YOU section above. Keep it concise (2-3 sentences). Do NOT suggest example queries.
- For thanks: Acknowledge graciously (1 sentence).
- For off-topic questions: Answer very briefly, then mention you specialize in cybersecurity.

Keep responses short (2-3 sentences max)."""

        return call_ollama(
            system_prompt=system_prompt,
            user_prompt=f"User said: '{prompt}'. Respond naturally as SecRAG.",
            temperature=config.get("ollama", {}).get("temperature_greeting", 0.8),
            max_tokens=300
        )
        
    except Exception as e:
        # Static fallback only if LLM completely fails
        if 'thank' in prompt.lower():
            return "You're welcome! 😊 Feel free to ask about any security topics!"
        else:
            return """👋 Hello! I'm **SecRAG**, your AI security analyst.

**I can help with:** Vulnerability analysis, penetration testing, CVE research, and security best practices.

**Try asking:** *"How to prevent SQL injection?"*"""


# ========================================
# SIDEBAR
# ========================================

with st.sidebar:
    st.title("🛡️ SecRAG")
    st.caption("Security RAG Assistant")
    st.markdown("---")

    st.markdown("### System Info")
    st.write(f"Model: {config['app']['model']} (Ollama)")
    st.write("Vector DB: Chroma")
    st.write("Server: HTTP (persistent)")
    
    # Server status
    server_status = check_server()
    if server_status:
        st.success("✅ Server: Online")
    else:
        st.error("❌ Server: Offline")
        st.caption("Start server: `python server.py`")
    
    st.markdown("---")
    st.markdown("### Output Mode")
    
    # Output mode selector
    if "output_mode" not in st.session_state:
        st.session_state.output_mode = "analysis"
    
    output_mode = st.radio(
        "Response Style:",
        options=["analysis", "checklist"],
        format_func=lambda x: "📊 Analysis Mode" if x == "analysis" else "✅ Checklist Mode",
        help="Analysis: Detailed explanations with 5 sections\nChecklist: Actionable pentesting tasks only",
        horizontal=True
    )
    st.session_state.output_mode = output_mode
    
    if output_mode == "checklist":
        st.info("💡 **Checklist Mode**: Get practical testing steps without theory")
    else:
        st.info("📚 **Analysis Mode**: Get comprehensive security analysis")
    
    st.markdown("---")
    st.markdown("### Options")
    


    if st.button("🗑️ Clear Chat"):
        st.session_state.messages = []
        st.rerun()


# ========================================
# MAIN INTERFACE
# ========================================

st.title("🔒 SecRAG - Security Intelligence")
st.caption("AI-powered security knowledge ")
st.markdown("---")

# Initialize Session
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])




# ========================================
# CHAT INPUT
# ========================================

if prompt := st.chat_input("Ask about vulnerabilities, exploits, or security best practices..."):

    # Block prompt injection
    if not is_safe_query(prompt):
        st.error("⚠️ Query blocked: potential prompt injection detected.")
        st.stop()
    
    # Check server (only for security queries that need RAG)
    if is_security_query(prompt) and not check_server():
        st.error("❌ Server offline. Start with: `python server.py`")
        st.stop()
    
    # Add user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # ========================================
    # SMART ROUTING: Greetings vs Security Queries
    # ========================================
    
    with st.chat_message("assistant"):
        
        if is_security_query(prompt):
            # ========================================
            # SECURITY QUERIES - Full RAG Pipeline
            # ========================================
            
            # Tool Call 1: Search
            with st.spinner("🔍 Searching knowledge base..."):
                search_result = call_tool("search", {
                    "query": prompt,
                    "k": 20
                })
            
            if "error" in search_result:
                st.error(f"Search failed: {search_result['error']}")
                st.stop()
            
            raw_chunks = search_result.get("chunks", [])
            
            if not raw_chunks:
                st.warning("No relevant results found in the knowledge base.")
                st.stop()
            


            # Tool Call 2: Rerank
            with st.spinner("🎯 Reranking results..."):
                rerank_result = call_tool("rerank", {
                    "query": prompt,
                    "chunks": raw_chunks,
                    "top_k": 5
                })

            if "error" in rerank_result:
                st.error(f"Reranking failed: {rerank_result['error']}")
                st.stop()
            
            reranked_chunks = rerank_result.get("chunks", [])
            
            # Show final sources that the LLM will actually read
            with st.expander("📚 Final Retrieved Sources (Sent to LLM)", expanded=False):
                for i, chunk in enumerate(reranked_chunks, 1):
                    score = chunk.get("relevance_score", 0)
                    source = chunk.get("source", "Unknown")
                    c_type = chunk.get("type", "unknown")
                    st.markdown(f"**{i}. {source} - {c_type}** (Relevance: `{score:.3f}`)")
                    st.text(chunk.get('content', ''))

            # Tool Call 3: Generate Report (Always-on — richest context for LLM)
            report_text = ""
            with st.spinner("📄 Generating security report..."):
                report_result = call_tool("generate_report", {
                    "findings": reranked_chunks,
                    "format": "markdown"
                })

            if "error" in report_result:
                st.error(f"Report generation failed: {report_result['error']}")
            else:
                report_text = report_result.get("report", "")
                
                if not report_text:
                    st.warning("Report was generated but is empty. Check server logs.")
        
            # Generate LLM Response
            with st.spinner("🤖 Generating response..."):
                
                def format_chunks(chunks):
                    """Format chunks for LLM context"""
                    if not chunks:
                        return "No relevant information found."
                    formatted = []
                    for i, chunk in enumerate(chunks, 1):
                        source = chunk.get("source", "Unknown")
                        content = chunk.get("content", "")
                        formatted.append(f"[Source {i}: {source}]\n{content}")
                    return "\n\n".join(formatted)
                
                
                # ========================================
                # DUAL-MODE SYSTEM PROMPTS
                # ========================================
                
                # Get output mode from session state
                output_mode = st.session_state.get("output_mode", "analysis")
                
                # System Prompt: Analysis Mode (Adaptive)
                SYSTEM_ANALYSIS_PROMPT = """You are SecRAG, an expert AI security analyst.

YOUR KNOWLEDGE: You may ONLY use information from the <SECURITY_REPORT> provided to you. Do NOT add facts, tools, techniques, or recommendations that are not explicitly present in the report.

ANTI-HALLUCINATION RULES:
1. Every claim you make MUST be supported by content in the <SECURITY_REPORT>.
2. If the report LACKS specific mitigation steps, you MUST state: "The retrieved data does not include detailed mitigation steps for this topic." and NOTHING ELSE. If the report DOES contain mitigation steps, list them and DO NOT include the disclaimer.
3. Do NOT invent tool names, code examples, or techniques not present in the report.

RESPONSE FORMAT — Adapt based on user intent:

• INTENT: Data Lookup (e.g., "XSS CVEs", "list vulnerabilities").
  → Output a Markdown table of findings with CVE IDs, CVSS scores, and descriptions.

• INTENT: Concept Explanation (e.g., "Explain XSS", "How to prevent SQLi").
  → Provide a comprehensive response with these sections:
     ## Overview — What the vulnerability is (from the report definitions)
     ## How It Works — The technical mechanism (from report details)
     ## Defense Strategies — Every mitigation/defense option mentioned in the report, explained clearly
     ## Related Findings — Relevant CVEs or CWEs from the report
     ## Key Takeaway — A concise summary

• INTENT: Targeted Question (e.g., "How do I fix CVE-1234").
  → Answer directly using report content. If the report lacks the answer, say so.

CRITICAL: Extract ALL relevant details from the report. Do not give shallow 2-sentence answers — synthesize the full depth of information available in the provided findings. Use markdown formatting for readability."""

                # System Prompt: Checklist Mode (Actionable)
                SYSTEM_CHECKLIST_PROMPT = """You are SecRAG, a senior penetration tester.

CRITICAL: Only extract testing steps from the provided context. Do NOT invent steps or tools not mentioned in the context.

Output format:
- Title: <Vulnerability or Topic>
- Checklist using [ ] items
- Each item must be a concrete, actionable test

Rules:
- Short, imperative sentences
- Include specific tools/commands from the context
- Group related checks together
- No explanations or theory"""

                # Select prompt based on mode
                if output_mode == "checklist":
                    system_prompt = SYSTEM_CHECKLIST_PROMPT
                else:
                    system_prompt = SYSTEM_ANALYSIS_PROMPT
                
                # Context prompt — always uses the report for richest metadata-backed context
                if report_text:
                    context_prompt = f"""<SECURITY_REPORT>
{report_text}
</SECURITY_REPORT>

<QUERY>
{prompt}
</QUERY>

Analyze the findings using only the information in the report above. Adhere strictly to the System Rules regarding formatting and hallucination."""
                else:
                    # Fallback: report failed, use raw chunks directly
                    context_prompt = f"""<CONTEXT>
{format_chunks(reranked_chunks)}
</CONTEXT>

<QUERY>
{prompt}
</QUERY>"""
                
                with st.expander("🔍 Reasoning Context", expanded=False):
                    st.code(f"SYSTEM:\n{system_prompt}\n\nCONTEXT:\n{context_prompt}", language="text")
                
                try:
                    response_text = call_ollama(
                        system_prompt=system_prompt,
                        user_prompt=context_prompt,
                        temperature=config.get("ollama", {}).get("temperature_analysis", 0.4),
                        max_tokens=4000
                    )
                    
                    st.markdown(response_text)

                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": response_text
                    })
                    
                except Exception as e:
                    error_msg = str(e)
                    st.error(f"⚠️ LLM Error: {error_msg}")
                    
                    # Provide fallback response with sources
                    fallback_response = f"""I encountered an error generating the full response, but here's what I found:

**Retrieved Sources:**
{len(reranked_chunks)} relevant security documents were found for your query: "{prompt}"

**Sources Include:**
"""
                    for i, chunk in enumerate(reranked_chunks[:3], 1):
                        source = chunk.get("source", "Unknown")
                        content_preview = chunk.get("content", "")[:200]
                        fallback_response += f"\n{i}. **{source}**: {content_preview}...\n"
                    
                    fallback_response += f"""

**Recommendation:** Try rephrasing your query or check the retrieved sources above for relevant information.

**Error Details:** {error_msg}"""
                    
                    st.markdown(fallback_response)
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": fallback_response
                    })
        
        else:
            # ========================================
            # CASUAL / GREETINGS - Direct LLM (No RAG)
            # ========================================
            with st.spinner("💬 Thinking..."):
                response_text = get_casual_response(prompt)
                st.markdown(response_text)
                
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response_text,
                    "type": "greeting"
                })