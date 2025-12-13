import ast
import sys
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ImportScanner:
    
    def scan_directory(self, path):
        root = Path(path)
        imports = set()
        file_count = 0
        
        for file in root.rglob("*.py"):
            try:
                file_imports = self.scan_file_(file)
                imports.update(file_imports)
                file_count += 1
            except Exception as e:
                logger.warning(f"Error scanning {file}: {e}")
        
        logger.info(f"Scanned {file_count} Python files")
        return imports
            
    
    def scan_file_(self, path):
        imports = set()
        try:
            with open(path, "r", encoding="utf-8") as file:
                tree = ast.parse(file.read(), filename=str(path))
        except SyntaxError as e:
            logger.warning(f"Syntax error in {path}: {e}")
            return imports
        except Exception as e:
            logger.warning(f"Could not parse {path}: {e}")
            return imports
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split('.')[0]
                    if top in sys.stdlib_module_names: 
                        continue                      
                    imports.add(top)
                    
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split('.')[0]
                    # Skip standard library
                    if top not in sys.stdlib_module_names:
                        imports.add(top)
                    
        return imports