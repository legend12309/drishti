def get_active_engines() -> dict:
    return {
        "recon": {"status": "ready", "description": "OSINT & DNS Topology Scanner"},
        "intel": {"status": "ready", "description": "ChromaDB + all-MiniLM-L6-v2 Embeddings & CVE Matcher"},
        "metasploit": {"status": "ready", "description": "Rapid7 Metasploit Weaponization & Exploit Matcher"},
        "graph": {"status": "ready", "description": "NetworkX Attack Graph Visualizer"},
        "guard": {"status": "ready", "description": "Llama-Prompt-Guard & Prompt Injection Defense"},
        "stix":  {"status": "ready", "description": "STIX 2.1 Threat Report Exporter"},
    }
