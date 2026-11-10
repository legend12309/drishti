import os
import shutil
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RELEASES_DIR = ROOT_DIR / "releases"
RELEASES_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_ZIP = RELEASES_DIR / "drishti-v1.0.0-standalone.zip"

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "releases",
}

EXCLUDE_FILES = {
    ".DS_Store",
    "desktop.ini",
}

def should_exclude(rel_path_str: str) -> bool:
    parts = rel_path_str.replace("\\", "/").split("/")
    for part in parts:
        if part in EXCLUDE_DIRS:
            return True
        if part.startswith(".") and part not in (".env", ".env.example"):
            return True
    filename = parts[-1]
    if filename.endswith(".pyc") or filename in EXCLUDE_FILES:
        return True
    return False

def build_standalone_zip():
    print(f"Building DRISHTI Standalone Distribution Archive: {OUTPUT_ZIP}...")
    
    # Ensure frontend/dist exists
    dist_dir = ROOT_DIR / "frontend" / "dist"
    if not dist_dir.exists():
        raise RuntimeError("frontend/dist does not exist! Run 'npm run build' inside frontend/ first.")

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(ROOT_DIR)
                rel_str = str(rel_path)

                if should_exclude(rel_str):
                    continue

                # In frontend/, ONLY include dist/ and package.json
                if rel_str.startswith("frontend\\") or rel_str.startswith("frontend/"):
                    if not (rel_str.startswith("frontend/dist") or rel_str.startswith("frontend\\dist") or rel_str == "frontend/package.json" or rel_str == "frontend\\package.json"):
                        continue

                zipf.write(full_path, arcname=f"drishti/{rel_str}")

    size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"[SUCCESS] Archive generated: {OUTPUT_ZIP} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    build_standalone_zip()
