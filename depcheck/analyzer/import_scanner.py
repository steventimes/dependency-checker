import ast
import sys
import logging
from pathlib import Path
from typing import Set, Dict, List

logger = logging.getLogger(__name__)


class ImportScanner:
    
    def scan_directory(self, path: Path) -> Set[str]:
        """Scans directory and returns a flat set of 3rd-party imports."""
        root = Path(path)
        imports = set()
        file_count = 0
        local_modules = self._get_local_modules(root)
        logger.debug(f"Identified local modules: {local_modules}")
        
        for file in root.rglob("*.py"):
            if any(part.startswith('.') for part in file.parts):
                continue

            try:
                file_imports = self.scan_file_(file)
                imports.update(file_imports)
                file_count += 1
            except Exception as e:
                logger.warning(f"Error scanning {file}: {e}")
        
        cleaned_imports = {
            imp for imp in imports 
            if imp not in local_modules
        }
        
        logger.info(f"Scanned {file_count} files. Found {len(cleaned_imports)} 3rd-party imports.")
        return cleaned_imports

    def generate_dot(self, project_root: Path, output_file: Path):
        """Generates a Graphviz .dot file for visualization."""
        graph_data = self._scan_for_graph(project_root)
        local_modules = self._get_local_modules(project_root)
        
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("digraph DepGraph {\n")
                f.write("  rankdir=LR;\n")
                f.write("  node [fontname=\"Helvetica\"];\n")
                f.write("  edge [fontsize=10];\n\n")
                f.write("  // Styles\n")
                f.write("  node [shape=box, style=filled, fillcolor=\"#E3F2FD\"]; // Python Files\n")
                
                for file_path, imports in graph_data.items():
                    node_id = f"file_{file_path.replace('/', '_').replace('.', '_')}"
                    f.write(f'  "{node_id}" [label="{file_path}"];\n')
                    
                    for imp in imports:
                        is_local = imp in local_modules
                        
                        imp_node = f"pkg_{imp}"
                        
                        if is_local:
                            f.write(f'  "{imp_node}" [shape=ellipse, style=filled, fillcolor="#FFF3E0", label="{imp}"];\n')
                            f.write(f'  "{node_id}" -> "{imp_node}" [style=dashed, color="grey"];\n')
                        else:
                            f.write(f'  "{imp_node}" [shape=ellipse, style=filled, fillcolor="#E8F5E9", label="{imp}"];\n')
                            f.write(f'  "{node_id}" -> "{imp_node}" [color="black"];\n')

                f.write("}\n")
            logger.info(f"Dependency graph saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write graph file: {e}")

    def _scan_for_graph(self, root: Path) -> Dict[str, Set[str]]:
        """Internal method to build a map of File -> [Imports]."""
        mapping = {}
        for file in root.rglob("*.py"):
            if any(part.startswith('.') for part in file.parts):
                continue
            
            try:
                rel_path = file.relative_to(root).as_posix()
                mapping[rel_path] = self.scan_file_(file)
            except Exception:
                continue
        return mapping

    def _get_local_modules(self, root: Path) -> Set[str]:
        locals_ = set()
        if not root.exists():
            return locals_
            
        for child in root.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_file() and child.suffix == ".py":
                locals_.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").exists():
                locals_.add(child.name)
        return locals_
    
    def scan_file_(self, path: Path) -> Set[str]:
        imports = set()
        try:
            with open(path, "r", encoding="utf-8") as file:
                tree = ast.parse(file.read(), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as e:
            logger.warning(f"Skipping {path.name}: {e}")
            return imports
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split('.')[0]
                    if top not in sys.stdlib_module_names:
                        imports.add(top)
                    
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split('.')[0]
                    if top not in sys.stdlib_module_names:
                        imports.add(top)
                    
        return imports