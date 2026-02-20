import streamlit as st
import os
import yaml
import requests
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# Configure Gemini API once at module level
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Page Config
st.set_page_config(page_title="SecRAG Intelligence", page_icon="🛡️", layout="wide")

# Load Config
def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()
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
# SMART GREETING DETECTION
# ========================================

def is_simple_greeting(text: str) -> bool:
    """Detect simple greetings (1-3 words)"""
    text_lower = text.lower().strip()
    words = text_lower.split()
    
    if len(words) <= 3:
        greeting_words = ['hi', 'hello', 'hey', 'greetings', 'good morning', 
                         'good afternoon', 'good evening', 'thanks', 'thank you']
        
        if any(text_lower.startswith(g) for g in greeting_words):
            return True
        if text_lower in greeting_words:
            return True
    
    return False


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


def get_greeting_response_llm(prompt: str) -> str:
    """
    Direct LLM call for greetings - Natural & Human-like!
    No RAG/Tools = Fast, but sounds natural
    """
    try:
        model = genai.GenerativeModel(
            model_name=config["app"]["model"],
            system_instruction="""You are SecRAG, a friendly AI security Expert.

For greetings: Welcome the user warmly (2-3 sentences), introduce yourself, and ask what security topic they'd like to explore.

For thanks: Acknowledge graciously and offer continued help.

Be conversational and natural, not robotic."""

        )
        llm_response = model.generate_content(
            contents=f"User said: '{prompt}'. Respond naturally as SecRAG, a security AI assistant.",
            generation_config=genai.GenerationConfig(
                max_output_tokens=300,
                temperature=0.8  # Higher for natural conversation
            )
        )
        
        # Check for empty response
        if llm_response.text and llm_response.text.strip():
            return llm_response.text
        else:
            raise ValueError("Empty LLM response")
        
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
    st.write("Model: Gemini")
    st.write("Vector DB: Chroma")
    st.write("Server: HTTP (persistent)")
    
    # Server status
    server_status = check_server()
    if server_status:
        st.success("✅ Server: Online")
    else:
        st.error("❌ Server: Offline")
        st.caption("Start server: `python mcpserver.py`")
    
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
    
    if "generate_report" not in st.session_state:
        st.session_state.generate_report = False
    
    st.session_state.generate_report = st.checkbox(
        "Generate Security Report",
        value=st.session_state.generate_report,
        help="Create a formatted pentest report from findings"
    )

    if st.button("🗑️ Clear Chat"):
        st.session_state.messages = []
        st.rerun()


# ========================================
# MAIN INTERFACE
# ========================================

st.title("🔒 SecRAG - Security Intelligence")
st.caption("AI-powered security knowledge with HTTP-based MCP")
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
    
    # Check server (only for non-greetings)
    if not is_simple_greeting(prompt) and not check_server():
        st.error("❌ Server offline. Start with: `python mcpserver.py`")
        st.stop()
    
    # Add user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # ========================================
    # SMART ROUTING: Greetings vs Security Queries
    # ========================================
    
    with st.chat_message("assistant"):
        
        if is_simple_greeting(prompt):
            # ========================================
            # GREETINGS - Direct LLM (No RAG, Natural!)
            # ========================================
            with st.spinner("💬 Thinking..."):
                response_text = get_greeting_response_llm(prompt)
                st.markdown(response_text)
                
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response_text,
                    "type": "greeting"
                })
        
        else:
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
            
            # Show retrieved sources
            with st.expander("📚 Retrieved Sources", expanded=False):
                for i, chunk in enumerate(raw_chunks[:5], 1):
                    st.caption(f"**{i}. {chunk.get('source', 'Unknown')} - {chunk.get('type', 'unknown')}**")
                    st.text(chunk.get('content', '')[:150] + "...")

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
            
            # Show reranking scores
            with st.expander("📊 Reranking Scores", expanded=False):
                for i, chunk in enumerate(reranked_chunks, 1):
                    score = chunk.get("relevance_score", 0)
                    source = chunk.get("source", "Unknown")
                    st.caption(f"{i}. {source} - Relevance: {score:.3f}")

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
                
                if report_text:
                    with st.expander("🧠 Analysis Context", expanded=False):
                        st.markdown(report_text)

                else:
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
                
                # System Prompt: Analysis Mode (Comprehensive)
                SYSTEM_ANALYSIS_PROMPT = """You are SecRAG, an AI security analyst specializing in penetration testing and vulnerability assessment.

CRITICAL: Only use information from the provided context. Do NOT add information from outside the context. If the context doesn't cover a section, state that no relevant information was found.

Structure your response as:
1. **Overview**: Brief explanation
2. **Technical Details**: How it works
3. **Testing Steps**: Step-by-step procedures
4. **Mitigation**: Prevention/fixes
5. **Tools**: Relevant security tools

Include only sections supported by the retrieved context. Be precise and security-focused."""

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

Analyze the findings using only the information in the report above. Structure your response around the report's findings with technical depth and actionable mitigation strategies."""
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
                    model = genai.GenerativeModel(
                        model_name=config["app"]["model"],
                        system_instruction=system_prompt
                    )

                    llm_response = model.generate_content(
                        contents=context_prompt,
                        generation_config=genai.GenerationConfig(
                            max_output_tokens=4000,
                            temperature=0.4
                        )
                    )
                    
                    # Check for blocked response (safety filters)
                    if not llm_response.candidates:
                        raise ValueError("Response blocked by safety filters. Try rephrasing your query.")
                    
                    response_text = llm_response.text
                    if not response_text or not response_text.strip():
                        raise ValueError("Empty response from Gemini LLM")
                    
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