def get_active_engines() -> dict:
    return {
        "recon": {"status": "ready", "description": "OSINT & DNS Topology Scanner"},
        "intel": {"status": "ready", "description": "ChromaDB + all-MiniLM-L6-v2 Embeddings"},
        "graph": {"status": "ready", "description": "NetworkX Attack Graph Visualizer"},
        "stix":  {"status": "ready", "description": "STIX 2.1 Threat Report Exporter"},
    }
