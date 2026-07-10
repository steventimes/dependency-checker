import ast
import os
import sys
import logging
from pathlib import Path
from typing import Set, Dict

logger = logging.getLogger(__name__)


class ImportScanner:
    IGNORED_DIRECTORIES = {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
    
    def scan_directory(self, path: Path) -> Set[str]:
        """Scans directory and returns a flat set of 3rd-party imports."""
        root = Path(path)
        imports: Set[str] = set()
        file_count = 0
        local_modules = self._get_local_modules(root)
        logger.debug(f"Identified local modules: {local_modules}")
        
        for file in self._iter_python_files(root):
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
        mapping: Dict[str, Set[str]] = {}
        for file in self._iter_python_files(root):
            try:
                rel_path = file.relative_to(root).as_posix()
                mapping[rel_path] = self.scan_file_(file)
            except Exception:
                continue
        return mapping

    def _get_local_modules(self, root: Path) -> Set[str]:
        locals_: Set[str] = set()
        if not root.exists():
            return locals_

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_dir(dirname)
            ]
            current_dir = Path(dirpath)
            if "__init__.py" in filenames:
                locals_.add(current_dir.name)
            for filename in filenames:
                if not filename.endswith(".py") or filename.startswith("."):
                    continue
                module_name = Path(filename).stem
                if module_name != "__init__":
                    locals_.add(module_name)
        return locals_

    def _iter_python_files(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_dir(dirname)
            ]
            current_dir = Path(dirpath)
            for filename in sorted(filenames):
                if filename.startswith(".") or not filename.endswith(".py"):
                    continue
                yield current_dir / filename

    def _should_ignore_dir(self, name: str) -> bool:
        return name.startswith(".") or name in self.IGNORED_DIRECTORIES
    
    def scan_file_(self, path: Path) -> Set[str]:
        imports: Set[str] = set()
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
