def normalize_imports(imported_modules):
    mapping = {
        "yaml": "pyyaml",
        "bs4": "beautifulsoup4",
        "PIL": "pillow",
        "sklearn": "scikit-learn",
        "cv2": "opencv-python",
        "dotenv": "python-dotenv",
        "git": "gitpython",
        "dateutil": "python-dateutil"
    }
    
    normalized = set()
    for module in imported_modules:
        if module in mapping:
            normalized.add(mapping[module])
        else:
            normalized.add(module.lower())
            
    return normalized