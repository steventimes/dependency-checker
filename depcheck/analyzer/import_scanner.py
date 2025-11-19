import ast
from pathlib import Path

class ImportScanner:
    
    def scan_directory(self, path):
        root = Path(path)
        imports = set()
        
        for file in root.rglob("*.py"):
            imports.update(self.scan_file_(file))
            
        return imports
            
    
    def scan_file_(self, path):
        imports = set()
        try:
            with open(path, "r", encoding="utf-8") as file:
                tree = ast.parse(file.read())
        except Exception:
            return imports
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split('.')[0]
                    imports.add(top)
                    
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split('.')[0]
                    imports.add(top)
                    
        return imports