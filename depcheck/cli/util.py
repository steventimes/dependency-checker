from pathlib import Path
from typing import Mapping, Set

try:
    from importlib.metadata import packages_distributions
except ImportError:
    def packages_distributions() -> Mapping[str, list[str]]:
        return {}


def normalize_imports(imported_modules: Set[str]) -> Set[str]:
    """
    Converts import names (e.g., 'yaml', 'sklearn') to package names 
    (e.g., 'PyYAML', 'scikit-learn').
    
    Priority:
    1. Check installed packages in the current environment (Best Accuracy).
    2. Check hardcoded fallback list.
    3. Default to the import name itself.
    """
    
    installed_map = packages_distributions()

    static_mapping = {
        "yaml": "pyyaml",
        "bs4": "beautifulsoup4",
        "PIL": "pillow",
        "sklearn": "scikit-learn",
        "cv2": "opencv-python",
        "dotenv": "python-dotenv",
        "git": "gitpython",
        "dateutil": "python-dateutil",
        "google.protobuf": "protobuf",
        "mysqldb": "mysqlclient",
        "kafka": "kafka-python",
        "jose": "python-jose",
        "jwt": "pyjwt",
        "paste": "pastedeploy",
        "boto3": "boto3", 
        "botocore": "botocore",
        "google.cloud.storage": "google-cloud-storage",
        "google.cloud.pubsub": "google-cloud-pubsub",
    }
    
    normalized = set()
    
    for module in imported_modules:
        if module in installed_map:
            dist_names = installed_map[module]
            if dist_names:
                normalized.add(dist_names[0])
                continue

        if module in static_mapping:
            normalized.add(static_mapping[module])
            continue

        normalized.add(module.lower())
            
    return normalized


def load_ignore_file(project_root: Path) -> Set[str]:
    """
    Loads a .depcheckignore file if it exists.
    Returns a set of package names to ignore.
    """
    ignore_file = project_root / ".depcheckignore"
    ignored = set()
    
    if ignore_file.exists():
        try:
            with open(ignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ignored.add(line.lower())
        except Exception as e:
            print(f"Warning: Could not read .depcheckignore: {e}")
            
    return ignored