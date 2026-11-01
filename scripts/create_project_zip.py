import os
import sys
import zipfile
import shutil
from pathlib import Path

# Fix Windows console encoding if needed
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

def create_zip():
    project_root = Path(__file__).resolve().parent.parent
    
    # Destination paths
    zip_root = project_root / "ForensicX_Project.zip"
    
    user_home = Path(os.environ.get("USERPROFILE", "C:/Users/koush"))
    downloads_dir = user_home / "Downloads"
    zip_downloads = downloads_dir / "ForensicX_Project.zip"
    
    desktop_dir = user_home / "Desktop"
    zip_desktop = desktop_dir / "ForensicX_Project.zip"

    # Folders and patterns to exclude
    exclude_dirs = {
        ".venv",
        "venv",
        ".git",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
    }
    
    exclude_files = {
        "ForensicX_Project.zip",
        "DF_Project.zip",
    }
    
    exclude_extensions = {
        ".pyc",
        ".pyo",
    }

    print("Creating archive from project directory...")
    total_files = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(zip_root, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_root):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]

            for file in files:
                if file in exclude_files:
                    continue
                ext = os.path.splitext(file)[1].lower()
                if ext in exclude_extensions:
                    continue
                if file.endswith("-shm") or file.endswith("-wal"):
                    continue

                full_path = Path(root) / file
                rel_path = full_path.relative_to(project_root)

                # Skip if inside an excluded directory path
                parts = rel_path.parts
                if any(p in exclude_dirs for p in parts):
                    continue

                zf.write(full_path, arcname=str(rel_path))
                total_files += 1
                total_uncompressed_bytes += full_path.stat().st_size

    compressed_size = zip_root.stat().st_size
    print(f"Archived {total_files} files.")
    print(f"Uncompressed: {total_uncompressed_bytes / (1024*1024):.2f} MB")
    print(f"Compressed: {compressed_size / (1024*1024):.2f} MB")
    print(f"Created in workspace: {zip_root.name}")

    # Copy to Downloads if available
    try:
        if downloads_dir.exists():
            shutil.copy2(zip_root, zip_downloads)
            print(f"Copied to Downloads folder: {zip_downloads}")
    except Exception as e:
        print(f"Could not copy to Downloads: {e}")

    # Copy to Desktop if available
    try:
        if desktop_dir.exists():
            shutil.copy2(zip_root, zip_desktop)
            print(f"Copied to Desktop folder: {zip_desktop}")
    except Exception as e:
        print(f"Could not copy to Desktop: {e}")

if __name__ == "__main__":
    create_zip()
