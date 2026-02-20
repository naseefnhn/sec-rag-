import os
import requests
from langchain_community.document_loaders import (
    UnstructuredMarkdownLoader,UnstructuredXMLLoader,
    DirectoryLoader,
    GitHubIssuesLoader,
    PyMuPDFLoader,
    JSONLoader,
    CSVLoader
)
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
import chromadb
import yaml
import xmltodict
from langchain_core.documents import Document
from tqdm import tqdm
from bs4 import BeautifulSoup


def load_config():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config

def clean_html_content(html_text: str) -> str:
    """
    Extract main content from HTML, removing navigation, sidebars, and boilerplate.
    Reduces OWASP HTML noise by 60-80%.
    """
    soup = BeautifulSoup(html_text, 'html.parser')
    
    # Remove noise elements (navigation, headers, footers, scripts)
    for tag in soup(['nav', 'header', 'footer', 'aside', 'script', 
                     'style', 'iframe', 'noscript', 'form']):
        tag.decompose()
    
    # Remove common OWASP noise by class/id
    noise_selectors = [
        'navigation', 'sidebar', 'toc', 'breadcrumb', 'menu',
        'footer', 'header-nav', 'site-header', 'site-footer',
        'skip-to-content', 'search', 'md-header', 'md-footer',
        'md-sidebar', 'md-nav', 'md-tabs'
    ]
    
    for selector in noise_selectors:
        # Remove by class
        for element in soup.find_all(class_=lambda x: x and selector in x.lower()):
            element.decompose()
        # Remove by id
        for element in soup.find_all(id=lambda x: x and selector in x.lower()):
            element.decompose()
    
    # Extract main content (try multiple strategies)
    main_content = (
        soup.find('main') or 
        soup.find('article') or 
        soup.find(class_=lambda x: x and 'content' in x.lower()) or
        soup.find('body')
    )
    
    if main_content:
        # Get clean text with proper spacing
        text = main_content.get_text(separator='\n', strip=True)
        # Remove excessive whitespace
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    # Fallback: get all text
    return soup.get_text(separator='\n', strip=True)

class DBBuilder:
    def __init__(self):
        self.config = load_config()
        self.client = chromadb.PersistentClient(path=self.config["database"]["path"])
        self.embeddings = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=self.config["database"]["embedding_model"]
        )   

        
        # Reset collection to prevent duplicates
        try:
            self.client.delete_collection(name=self.config["database"]["collection_name"])
            print(f"🗑️ Deleted existing collection: {self.config['database']['collection_name']}")
        except Exception:
            pass # Collection didn't exist
            
        self.collection = self.client.get_or_create_collection(name=self.config["database"]["collection_name"], embedding_function=self.embeddings)
        self.text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=400)

    def load_owasp(self):
        """Load OWASP cheat sheets using requests + BeautifulSoup for proper HTML cleaning"""
        docs = []
        print("📥 Loading OWASP cheat sheets...")
        
        urls = [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
        ]

        for url in urls:
            try:
                # Fetch raw HTML (not pre-stripped like WebBaseLoader)
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                # Clean HTML while structure still exists
                cleaned_content = clean_html_content(response.text)
                
                title = url.split('/')[-1].replace("_", " ").replace(".html", "")

                # Assign priority based on common attack types
                if any(word in title.lower() for word in ["injection", "xss", "csrf", "sql", "authentication"]):
                    priority = "critical"
                elif any(word in title.lower() for word in ["session", "cookie", "password"]):
                    priority = "high"
                else:
                    priority = "medium"

                doc = Document(
                    page_content=cleaned_content,
                    metadata={
                        "source": "OWASP",
                        "type": "cheat-sheet",
                        "url": url,
                        "priority": priority,
                        "title": title
                    }
                )
                docs.append(doc)
                print(f"✓ Loaded & cleaned: {url.split('/')[-1]}")
            
            except Exception as e:
                print(f"✗ Failed {url}: {e}")

        return docs

    def load_owasp_guidelines(self):
        """Load OWASP WSTG PDF"""
        docs = []
        file_path = "knowledge_base/wstg-v4.2.pdf"

        if not os.path.exists(file_path):
            print(f"⚠️ File not found: {file_path}")
            return docs

        loader = PyMuPDFLoader(file_path)
        loaded_docs = loader.load()

        for i, page in enumerate(loaded_docs):
            page.metadata.update({
                "source": "OWASP_WSTG",
                "category": "web_security_test",
                "type": "guideline",
                "title": "OWASP Web Security Testing Guide v4.2",
                "page_number": i + 1,
                "priority": "high"
            })
            docs.append(page)

        print(f"✓ Loaded: {file_path.split('/')[-1]} ({len(docs)} pages)")
        return docs 


    def load_cve(self):
        """
        Enhanced CVE loading with inline filtering and deduplication
        - Web security focus
        - CVSS ≥ 4.0
        - Last 18 months
        - Deduplicates CVEs across files
        - Enhanced content formatting with CVE ID and date
        """
        import json
        from datetime import datetime, timezone
        
        print("\n📥 Loading CVEs with filtering...")
        
        docs = []
        filepaths = [
            "knowledge_base/nvdcve-2.0-modified.json",
            "knowledge_base/nvdcve-2.0-2025.json"
        ]
        
        # Filter criteria
        web_keywords = [
            'xss', 'cross-site', 'csrf', 'sql injection', 'sqli',
            'authentication', 'authorization', 'session', 'cookie',
            'api', 'rest', 'graphql', 'jwt', 'oauth',
            'deserialization', 'xxe', 'file upload', 'path traversal',
            'clickjacking', 'redirect', 'ssrf',
            'web application', 'http', 'javascript', 'php', 'python', 'java', 'remote code execution', 'rce'
        ]
        
        exclude_keywords = [
            'denial of service', 'dos attack', 'memory corruption',
            'buffer overflow', 'hardware', 'firmware', 'driver', 'kernel'
        ]
        
        total = 0
        filtered = 0
        duplicates = 0
        seen_cve_ids = set()  # Track CVE IDs to prevent duplicates
        
        for file in filepaths:
            if not os.path.exists(file):
                print(f"⚠️ File not found: {file}")
                continue
            
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for vuln in data['vulnerabilities']:
                total += 1
                cve = vuln['cve']
                cve_id = cve['id']
                
                # Filter 0: Deduplication - skip if already seen
                if cve_id in seen_cve_ids:
                    duplicates += 1
                    continue
                
                desc = cve['descriptions'][0]['value']
                desc_lower = desc.lower()
                
                # Filter: Skip rejected CVEs
                if '** REJECT **' in desc or '** RESERVED **' in desc:
                    continue
                
                # Filter 1: Must have web security keywords
                if not any(kw in desc_lower for kw in web_keywords):
                    continue
                
                # Filter 2: Exclude noise
                if any(exc in desc_lower for exc in exclude_keywords):
                    continue
                
                # Filter 3: Check age (last 18 months) - FIXED TIMEZONE BUG
                try:
                    published = cve.get('published', '')
                    if published:
                        # Parse the ISO format date
                        pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                        
                        # THE FIX: If the date has no timezone, force it to UTC
                        if pub_date.tzinfo is None:
                            pub_date = pub_date.replace(tzinfo=timezone.utc)
                        
                        # Now subtraction works (Aware - Aware)
                        age_days = (datetime.now(timezone.utc) - pub_date).days
                        
                        if age_days > 545:  # 18 months
                            continue
                except Exception as e:
                    # Log errors for debugging instead of silencing them
                    print(f"⚠️ Date parsing error for {cve_id}: {e}")
                    continue
                
                # Filter 4: Check CVSS (≥4.0)
                try:
                    metrics = vuln.get('cve', {}).get('metrics', {})
                    cvss_score = None
                    
                    # Try v3.1, then v3.0, then v2
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    if cvss_score and cvss_score < 4.0:
                        continue
                except:
                    pass  # If CVSS extraction fails, still include it
                
                # Passed all filters!
                filtered += 1
                seen_cve_ids.add(cve_id)  # Mark as seen
                
                # Create document with enhanced content formatting
                doc = Document(
                    page_content=f"{cve_id}\nPublished: {published[:10]}\n\n{desc}",
                    metadata={
                        "source": "NVD",
                        "category": "vulnerability",
                        "type": "cve",
                        "format": "json",
                        "cve_id": cve_id,
                        "cvss_score": cvss_score if cvss_score else 0.0,
                        "published": published,
                        "file_path": file
                    }
                )
                docs.append(doc)
            
            print(f"✓ Processed {file.split('/')[-1]} - {len(docs)} unique CVEs so far")
        
        print(f"✓ Total: {filtered} unique CVEs loaded (filtered {total - filtered - duplicates} irrelevant, {duplicates} duplicates from {total} total)")
        return docs


    def extract_cwe_text(self, field):
        """Extract clean text from CWE XML dict/list structures"""
        if isinstance(field, str):
            return field
        if isinstance(field, (dict, list)):
            items = field.values() if isinstance(field, dict) else field
            return ' '.join(self.extract_cwe_text(item) for item in items if item)
        return str(field) if field else ""

    def load_cwe(self):
        """
        Enhanced CWE loading with inline filtering
        - SANS Top 25 + Web Security CWEs only
        - Reduces from 900+ to ~60 high-impact weaknesses
        """
        print("\n📥 Loading CWEs with filtering...")
        
        docs = []
        filepath = r"knowledge_base\cwec_v4.18.xml"

        if not os.path.exists(filepath):
            print(f"⚠️ File not found: {filepath}")
            return docs

        with open(filepath, "r", encoding="utf-8") as f:
            data = xmltodict.parse(f.read())

        weaknesses = data["Weakness_Catalog"]["Weaknesses"]["Weakness"]
        
        # Priority CWEs (SANS Top 25 + Web + API)
        priority_cwes = {
            # SANS Top 25 (2024)
            "79",   # XSS
            "787",  # Out-of-bounds Write
            "89",   # SQL Injection
            "416",  # Use After Free
            "78",   # OS Command Injection
            "20",   # Improper Input Validation
            "125",  # Out-of-bounds Read
            "22",   # Path Traversal
            "352",  # CSRF
            "434",  # Unrestricted Upload
            "862",  # Missing Authorization
            "476",  # NULL Pointer Dereference
            "287",  # Improper Authentication
            "190",  # Integer Overflow
            "502",  # Deserialization of Untrusted Data
            "77",   # Command Injection
            "119",  # Buffer Overflow
            "798",  # Hard-coded Credentials
            "918",  # SSRF
            "306",  # Missing Authentication
            "362",  # Race Condition
            "269",  # Improper Privilege Management
            "94",   # Code Injection
            "863",  # Incorrect Authorization
            "276",  # Incorrect Default Permissions
            
            # Additional Web Security CWEs
            "601",  # URL Redirection
            "611",  # XXE
            "643",  # XPath Injection
            "732",  # Incorrect Permission Assignment
            "829",  # Inclusion of Functionality from Untrusted Control Sphere
            "917",  # Expression Language Injection
            "1021", # Improper Restriction of Rendered UI Layers
            "1275", # Sensitive Cookie without 'HttpOnly' Flag
            "327",  # Broken Crypto
            "330",  # Insufficient Randomness
            "522",  # Insufficiently Protected Credentials
            "532",  # Information Exposure Through Log Files
            "759",  # Use of One-Way Hash without Salt
            "916",  # Use of Password Hash with Insufficient Computational Effort
            
            # API Security CWEs
            "639",  # Insecure Direct Object Reference
            "284",  # Improper Access Control
            "285",  # Improper Authorization
            "668",  # Exposure of Resource to Wrong Sphere
            "770",  # Allocation of Resources Without Limits
            "307",  # Improper Restriction of Excessive Authentication Attempts
        }
        
        total = len(weaknesses)
        loaded = 0
        
        for w in weaknesses:
            cwe_id = w.get("@ID")
            
            # Filter: Only priority CWEs
            if cwe_id not in priority_cwes:
                continue
            
            loaded += 1
            
            name = w.get("@Name", "")
            desc = w.get("Description", "") or ""
            extended = w.get("Extended_Description", "") or ""
            
            # Fix: Extract clean text from XML dict structures
            desc = self.extract_cwe_text(desc)
            extended = self.extract_cwe_text(extended)

            # Collect consequences
            consequences = []
            con = w.get("Common_Consequences", {}).get("Consequence", [])
            if isinstance(con, dict):
                con = [con]

            for c in con:
                scope = c.get("Scope", "")
                impact = c.get("Impact", "")
                if isinstance(scope, list):
                    scope = ", ".join(scope)
                if isinstance(impact, list):
                    impact = ", ".join(impact)
                consequences.append(f"{scope}: {impact}")

            # Build final document text
            content = (
                f"CWE-{cwe_id}: {name}\n\n"
                f"{desc}\n\n"
                f"{extended}\n\n"
                f"Consequences:\n" + "\n".join(consequences)
            )

            docs.append(
                Document(
                    page_content=content,
                    metadata={
                        "source": "MITRE",
                        "type": "cwe",
                        "cwe_id": cwe_id,
                        "name": name,
                        "file_path": filepath,
                        "priority": "high"  # Mark as high priority
                    }
                )
            )

        print(f"✓ Loaded {loaded} priority CWEs (filtered {total - loaded} from {total})")
        return docs

        
    def build(self):
        """Build with smart chunking: CVEs stay atomic, everything else gets split"""
        
        # Load all documents
        owasp_docs = self.load_owasp()
        wstg_docs = self.load_owasp_guidelines()
        cve_docs = self.load_cve()
        cwe_docs = self.load_cwe()
        
        if not (owasp_docs or wstg_docs or cve_docs or cwe_docs):
            print("No documents loaded. Exiting.")
            return

        # Smart chunking: CVEs are atomic, don't split them
        all_chunks = []
        all_chunks.extend(cve_docs)  # CVEs: Add as-is (already self-contained)
        
        # Everything else: Use text splitter
        other_docs = owasp_docs + wstg_docs + cwe_docs
        print("🔄 Splitting non-CVE documents...")
        split_docs = self.text_splitter.split_documents(other_docs)
        all_chunks.extend(split_docs)
        
        print(f"✓ Total chunks: {len(all_chunks)} ({len(cve_docs)} CVEs + {len(split_docs)} others)")

        # Batch processing
        batch_size = 100
        print(f"🚀 Adding documents to collection in batches of {batch_size}...")
        
        for i in tqdm(range(0, len(all_chunks), batch_size), desc="Indexing"):
            batch = all_chunks[i:i + batch_size]
            
            ids = [f"doc_{i+j}" for j in range(len(batch))]
            texts = [d.page_content for d in batch]
            metadata = [d.metadata for d in batch]
            
            # Sanitize metadata to remove None values
            sanitized_metadata = [{k: v for k, v in m.items() if v is not None} for m in metadata]
            
            self.collection.add(ids=ids, documents=texts, metadatas=sanitized_metadata)

        print(f"✓ Total documents added to collection: {len(all_chunks)}")
        
if __name__ == "__main__":
    db_builder = DBBuilder()
    db_builder.build()